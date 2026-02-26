import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api, numericScore, severityFromRiskScore, severityLabel, statusLabel } from '../api/client';

function severityClass(severity) {
  return `sev sev-${severityLabel(severity)}`;
}

function caseStatusText(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'to_do') return 'new';
  if (value === 'in_progress') return 'investigating';
  if (value === 'done') return 'resolved';
  return statusLabel(status).toLowerCase();
}

function caseStatusClass(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'in_progress') return 'case-status case-status-investigating';
  if (value === 'done') return 'case-status case-status-resolved';
  if (value === 'to_do') return 'case-status case-status-new';
  return 'case-status';
}

export default function CasesPage() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const ticketsQuery = useQuery({
    queryKey: ['tickets', 'cases', statusFilter, search],
    queryFn: () => api.getTickets({ status: statusFilter, q: search }),
    refetchInterval: 8000,
  });

  const tickets = useMemo(() => {
    const rows = ticketsQuery.data?.tickets || [];
    return rows.filter((ticket) => {
      const displayRisk = numericScore(ticket.display_risk_score ?? ticket.decision_risk_score ?? ticket.risk_score);
      const displaySeverity = severityFromRiskScore(displayRisk, ticket.effective_severity || ticket.severity);
      if (severityFilter !== 'all' && displaySeverity !== severityFilter) {
        return false;
      }
      return true;
    });
  }, [ticketsQuery.data, severityFilter]);

  return (
    <section className="cases-page card panel">
      <div className="cases-toolbar cases-toolbar-poc">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search cases..."
        />
        <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
          <option value="all">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unknown">Unknown</option>
        </select>
        <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
          <option value="all">All Status</option>
          <option value="to_do">To Do</option>
          <option value="in_progress">In Progress</option>
          <option value="done">Done</option>
        </select>
        <button type="button" className="btn btn-newcase" title="Create case in pipeline workflow">
          + New Case
        </button>
      </div>

      <div className="cases-table-wrap">
        <table className="cases-table">
          <thead>
            <tr>
              <th>Case</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Score</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {!tickets.length && (
              <tr>
                <td colSpan={5} className="empty-cell">No cases found.</td>
              </tr>
            )}
            {tickets.map((ticket) => (
              <tr key={ticket.id}>
                {(() => {
                  const displayRisk = numericScore(ticket.display_risk_score ?? ticket.decision_risk_score ?? ticket.risk_score);
                  const displaySeverity = severityFromRiskScore(displayRisk, ticket.effective_severity || ticket.severity);
                  const scoreLabel = displayRisk == null ? '-' : (Number.isInteger(displayRisk) ? String(displayRisk) : displayRisk.toFixed(1));
                  return (
                    <>
                      <td>
                        <Link to={`/cases/${ticket.id}`} className="case-link">
                          <span className={`case-dot case-dot-${displaySeverity}`} />
                          <span className="case-main">
                            <span className="case-meta-line">
                              <span className="case-key">{ticket.ticket_key}</span>
                              {(ticket.action || ticket.classification || ticket.pipeline_score != null) && <span className="case-ai-tag">AI</span>}
                            </span>
                            <span className="case-title">{ticket.title}</span>
                            <span className="case-tags">
                              {ticket.classification && <span className="case-tag">{String(ticket.classification).toUpperCase()}</span>}
                              {ticket.verdict && <span className="case-tag">{String(ticket.verdict).replace(/_/g, ' ')}</span>}
                            </span>
                          </span>
                        </Link>
                      </td>
                      <td><span className={severityClass(displaySeverity)}>{severityLabel(displaySeverity)}</span></td>
                      <td><span className={caseStatusClass(ticket.status)}>{caseStatusText(ticket.status)}</span></td>
                      <td>{scoreLabel}</td>
                      <td>{ticket.created_at ? new Date(ticket.created_at).toLocaleDateString() : '-'}</td>
                    </>
                  );
                })()}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
