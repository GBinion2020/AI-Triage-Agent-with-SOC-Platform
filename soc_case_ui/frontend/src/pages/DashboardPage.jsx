import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ArrowUpRight, Clock, ShieldCheck, TrendingUp } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, numericScore, severityFromRiskScore, severityLabel, shortDate, statusLabel } from '../api/client';

function severityClass(severity) {
  return `sev sev-${severityLabel(severity)}`;
}

function statusClass(status) {
  return `status status-${String(status || '').toLowerCase()}`;
}

export default function DashboardPage() {
  const queryClient = useQueryClient();
  const [llmProvider, setLlmProvider] = useState('external');
  const [pipelineArch, setPipelineArch] = useState('orchestrated');
  const [cursor, setCursor] = useState(0);
  const [sessionId, setSessionId] = useState(null);
  const [runStatus, setRunStatus] = useState('idle');
  const [runTicketId, setRunTicketId] = useState(null);
  const [runSessionLabel, setRunSessionLabel] = useState('-');
  const [logLines, setLogLines] = useState([]);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState('');
  const logRef = useRef(null);

  const ticketsQuery = useQuery({
    queryKey: ['tickets', 'dashboard'],
    queryFn: () => api.getTickets({ status: 'all', q: '' }),
    refetchInterval: 8000,
  });

  const tickets = useMemo(() => ticketsQuery.data?.tickets || [], [ticketsQuery.data]);
  const stats = useMemo(() => {
    const critical = tickets.filter((ticket) => {
      const risk = numericScore(ticket.display_risk_score ?? ticket.decision_risk_score ?? ticket.risk_score);
      return severityFromRiskScore(risk, ticket.effective_severity || ticket.severity) === 'critical';
    }).length;
    const investigating = tickets.filter((ticket) => String(ticket.status) === 'in_progress').length;
    const resolved = tickets.filter((ticket) => String(ticket.status) === 'done').length;
    return { total: tickets.length, critical, investigating, resolved };
  }, [tickets]);

  useEffect(() => {
    let canceled = false;
    const poll = async () => {
      try {
        const status = await api.getPipelineStatus();
        if (canceled) return;
        setRunStatus(status.status || 'idle');
        setRunSessionLabel(status.session_id || '-');
        if (status.ticket_id) {
          setRunTicketId(status.ticket_id);
        }
        if (status.session_id && status.session_id !== sessionId) {
          setSessionId(status.session_id);
          setCursor(0);
          setLogLines([]);
        }
      } catch (_error) {
        // Keep UI running during transient endpoint failures.
      }
    };
    poll();
    const timer = setInterval(poll, 2500);
    return () => {
      canceled = true;
      clearInterval(timer);
    };
  }, [sessionId]);

  useEffect(() => {
    let canceled = false;
    const pollLogs = async () => {
      try {
        const response = await api.getPipelineLogs(cursor);
        if (canceled) return;

        if (response.session_id && response.session_id !== sessionId) {
          setSessionId(response.session_id);
          setCursor(0);
          setLogLines([]);
          return;
        }

        const lines = Array.isArray(response.lines) ? response.lines : [];
        if (lines.length) {
          setLogLines((prev) => {
            const merged = [...prev, ...lines];
            return merged.slice(-1200);
          });
        }
        setCursor(Number(response.next_cursor || 0));
        if (response.ticket_id) {
          setRunTicketId(response.ticket_id);
        }
      } catch (_error) {
        // Ignore transient log polling failures.
      }
    };

    pollLogs();
    const timer = setInterval(pollLogs, 2000);
    return () => {
      canceled = true;
      clearInterval(timer);
    };
  }, [cursor, sessionId]);

  useEffect(() => {
    if (!logRef.current) return;
    logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  async function startPipeline() {
    setError('');
    setIsStarting(true);
    try {
      const response = await api.startPipeline({ llm_provider: llmProvider, pipeline_arch: pipelineArch });
      setSessionId(response.session_id || null);
      setRunSessionLabel(response.session_id || '-');
      setRunStatus(response.status || 'running');
      setCursor(0);
      setRunTicketId(null);
      setLogLines([]);
      queryClient.invalidateQueries({ queryKey: ['tickets', 'dashboard'] });
    } catch (err) {
      setError(err.message || 'Failed to start pipeline');
    } finally {
      setIsStarting(false);
    }
  }

  return (
    <section className="dashboard-page">
      <div className="hero">
        <div>
          <h1>SOC Overview</h1>
          <p>{new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
        </div>
        <Link className="btn btn-ghost" to="/cases">
          All Cases <ArrowUpRight size={14} />
        </Link>
      </div>

      <div className="stat-grid">
        <article className="card stat-card">
          <div className="stat-head"><span>Total Cases</span><TrendingUp size={14} /></div>
          <div className="stat-value">{stats.total}</div>
          <div className="stat-sub">All time</div>
        </article>
        <article className="card stat-card">
          <div className="stat-head"><span>Critical</span><AlertTriangle size={14} /></div>
          <div className="stat-value">{stats.critical}</div>
          <div className="stat-sub">Immediate action</div>
        </article>
        <article className="card stat-card">
          <div className="stat-head"><span>Investigating</span><Clock size={14} /></div>
          <div className="stat-value">{stats.investigating}</div>
          <div className="stat-sub">In progress</div>
        </article>
        <article className="card stat-card">
          <div className="stat-head"><span>Resolved</span><ShieldCheck size={14} /></div>
          <div className="stat-value">{stats.resolved}</div>
          <div className="stat-sub">Closed out</div>
        </article>
      </div>

      <div className="workspace-grid">
        <article className="card panel">
          <header className="panel-head"><h2>Recent Cases</h2></header>
          <div className="recent-list">
            {!tickets.length && <div className="empty-state">No cases found.</div>}
            {tickets.slice(0, 12).map((ticket) => (
              (() => {
                const risk = numericScore(ticket.display_risk_score ?? ticket.decision_risk_score ?? ticket.risk_score);
                const severity = severityFromRiskScore(risk, ticket.effective_severity || ticket.severity);
                return (
                  <Link key={ticket.id} className="recent-item" to={`/cases/${ticket.id}`}>
                    <div className="recent-main">
                      <span className="recent-key">{ticket.ticket_key}</span>
                      <span className="recent-title">{ticket.title}</span>
                    </div>
                    <div className="recent-meta">
                      <span className={statusClass(ticket.status)}>{statusLabel(ticket.status)}</span>
                      <span className={severityClass(severity)}>{severityLabel(severity)}</span>
                    </div>
                  </Link>
                );
              })()
            ))}
          </div>
        </article>

        <article className="card panel pipeline-panel">
          <header className="panel-head"><h2>Pipeline Session</h2></header>
          <div className="pipeline-controls">
            <label>
              LLM Provider
              <select value={llmProvider} onChange={(event) => setLlmProvider(event.target.value)}>
                <option value="external">External</option>
                <option value="local">Local</option>
              </select>
            </label>
            <label>
              Pipeline Mode
              <select value={pipelineArch} onChange={(event) => setPipelineArch(event.target.value)}>
                <option value="orchestrated">Orchestrated</option>
                <option value="legacy">Legacy</option>
              </select>
            </label>
            <button type="button" className="btn btn-primary" onClick={startPipeline} disabled={isStarting || runStatus === 'running'}>
              {isStarting ? 'Starting...' : 'Start Pipeline'}
            </button>
            {error && <div className="inline-error">{error}</div>}
          </div>
          <div className="status-grid">
            <div><span>Run Status</span><strong>{statusLabel(runStatus)}</strong></div>
            <div><span>Session</span><strong className="mono truncate">{runSessionLabel}</strong></div>
            <div>
              <span>Ticket</span>
              <strong>{runTicketId ? <Link to={`/cases/${runTicketId}`}>SOC-{String(runTicketId).padStart(5, '0')}</Link> : '-'}</strong>
            </div>
          </div>
          <div className="terminal-wrap">
            <div className="terminal-head">Live Pipeline Reasoning Stream</div>
            <pre ref={logRef} className="terminal-log">
              {logLines.join('\n')}
            </pre>
          </div>
        </article>
      </div>
    </section>
  );
}
