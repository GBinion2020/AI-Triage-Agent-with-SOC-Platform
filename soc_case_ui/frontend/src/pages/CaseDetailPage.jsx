import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Bot, Clock, Network } from 'lucide-react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, severityFromRiskScore, severityLabel, shortDate, statusLabel } from '../api/client';
import AuditGraph from '../components/AuditGraph';
import IOCChip from '../components/IOCChip';
import InvestigationPanel from '../components/InvestigationPanel';

const STATUS_OPTIONS = ['to_do', 'in_progress', 'done'];

function severityClass(severity) {
  return `sev sev-${severityLabel(severity)}`;
}

function statusClass(status) {
  return `status status-${String(status || '').toLowerCase()}`;
}

function confidenceLabel(score) {
  const value = Number(score || 0);
  if (value >= 80) return 'Critical Risk';
  if (value >= 60) return 'High Risk';
  if (value >= 40) return 'Medium Risk';
  return 'Low Risk';
}

function riskTone(score) {
  const value = Number(score);
  if (!Number.isFinite(value)) return 'unknown';
  if (value >= 80) return 'critical';
  if (value >= 60) return 'high';
  if (value >= 40) return 'medium';
  return 'low';
}

function actionLabel(value) {
  const text = String(value || 'pending').replace(/_/g, ' ').trim();
  if (!text) return 'pending';
  return text;
}

function actionClass(value) {
  const action = String(value || '').toLowerCase();
  if (action.includes('escalate')) return 'action-pill action-escalate';
  if (action.includes('block')) return 'action-pill action-block';
  if (action.includes('close')) return 'action-pill action-close';
  if (action.includes('monitor')) return 'action-pill action-monitor';
  return 'action-pill';
}

function asInlineText(value, fallback = '—') {
  if (value === null || value === undefined || value === '') {
    return fallback;
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return String(value);
  }
}

function asBlockText(value, fallback = '-') {
  if (value === null || value === undefined || value === '') {
    return fallback;
  }
  if (typeof value === 'string') {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function isPlaceholderNarrative(value) {
  const text = String(value || '').trim().toLowerCase();
  if (!text) {
    return true;
  }
  return (
    text.startsWith('no analyst close note is saved yet')
    || text.startsWith('no evidence summary available')
    || text.startsWith('no evidence events captured for this case yet')
  );
}

function extractNarrativeFromFinding(value, depth = 0) {
  if (!value || depth > 5) {
    return '';
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text || text === '{}' || text === '[]') {
      return '';
    }
    return text;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const candidate = extractNarrativeFromFinding(item, depth + 1);
      if (candidate) {
        return candidate;
      }
    }
    return '';
  }
  if (typeof value === 'object') {
    const preferredKeys = [
      'reason',
      'summary',
      'parsed_decision',
      'decision',
      'description',
      'detail',
      'message',
      'analysis',
      'conclusion',
      'rationale',
      'finding',
      'output',
      'result',
      'raw_result',
      'raw_response',
    ];
    for (const key of preferredKeys) {
      const candidate = extractNarrativeFromFinding(value[key], depth + 1);
      if (candidate) {
        return candidate;
      }
    }
    for (const child of Object.values(value)) {
      const candidate = extractNarrativeFromFinding(child, depth + 1);
      if (candidate) {
        return candidate;
      }
    }
  }
  return '';
}

function deriveEventSummary(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return '';
  }
  const parts = events
    .slice(0, 3)
    .map((event) => {
      const eventName = String(event?.event || '').trim();
      const description = String(event?.description || '').trim();
      if (eventName && description) {
        return `${eventName}: ${description}`;
      }
      return eventName || description;
    })
    .filter(Boolean);

  if (!parts.length) {
    return '';
  }
  return parts.join(' | ');
}

function extractNumericScore(value) {
  if (value == null || value === '') {
    return null;
  }
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric;
  }
  const text = String(value);
  const patterns = [
    /final[\s_-]*score[^0-9-]*(-?\d+(?:\.\d+)?)/i,
    /risk[\s_-]*score[^0-9-]*(-?\d+(?:\.\d+)?)/i,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (!match) {
      continue;
    }
    const parsed = Number(match[1]);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function looksStructuredPayload(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) {
    return false;
  }
  return (
    (trimmed.startsWith('{') && trimmed.endsWith('}'))
    || (trimmed.startsWith('[') && trimmed.endsWith(']'))
  );
}

function extractInvestigationSummaryFromJiraDescription(description) {
  const text = String(description || '').trim();
  if (!text) {
    return '';
  }
  const match = text.match(/investigation\s+summary\s*:?\*?\s*(.+?)(?:\n-{3,}|\n\s*evidence\s+table\b|$)/is);
  if (!match) {
    return '';
  }
  return String(match[1] || '').trim();
}

function normalizeNarrativeCandidate(value) {
  if (value && typeof value === 'object') {
    const nested = extractNarrativeFromFinding(value);
    if (!nested || looksStructuredPayload(nested)) {
      return '';
    }
    return String(nested).trim();
  }

  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  if (!looksStructuredPayload(text)) {
    return text;
  }
  try {
    const parsed = JSON.parse(text);
    const extracted = extractNarrativeFromFinding(parsed);
    if (!extracted || looksStructuredPayload(extracted)) {
      return '';
    }
    return String(extracted).trim();
  } catch (_error) {
    return '';
  }
}

function resolveEvidenceSummary(overview) {
  function cleanSummary(raw) {
    const text = String(raw || '').trim();
    if (!text) {
      return '';
    }
    const lines = text
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .filter((line) => !/^wave\s+\d+\s*:?$/i.test(line))
      .map((line) => line.replace(/^\-\s*/, ''));
    if (!lines.length) {
      return '';
    }
    return lines.join('; ');
  }

  const evidenceSummary = String(overview?.evidence_summary || '').trim();
  if (!isPlaceholderNarrative(evidenceSummary)) {
    const cleaned = cleanSummary(evidenceSummary);
    if (cleaned) {
      return cleaned;
    }
  }
  const derived = deriveEventSummary(overview?.events);
  if (derived) {
    return derived;
  }
  return evidenceSummary || 'No evidence summary available.';
}

function extractFallbackSummary(overview, jiraSummary = '') {
  if (jiraSummary && !isPlaceholderNarrative(jiraSummary)) {
    return jiraSummary;
  }

  const rawSummary = normalizeNarrativeCandidate(overview?.summary);
  if (!isPlaceholderNarrative(rawSummary)) {
    return rawSummary;
  }

  const confidenceRationale = normalizeNarrativeCandidate(overview?.confidence_rationale);
  if (!isPlaceholderNarrative(confidenceRationale)) {
    return confidenceRationale;
  }

  const evidenceSummary = resolveEvidenceSummary(overview);
  if (!isPlaceholderNarrative(evidenceSummary)) {
    return evidenceSummary;
  }

  const journal = Array.isArray(overview?.triage_journal) ? overview.triage_journal : [];
  for (let idx = journal.length - 1; idx >= 0; idx -= 1) {
    const findingText = extractNarrativeFromFinding(journal[idx]?.finding);
    if (findingText) {
      return findingText;
    }
  }

  const eventSummary = deriveEventSummary(overview?.events);
  if (eventSummary) {
    return eventSummary;
  }

  return 'Pipeline finished without a captured analyst narrative. Review IOC and evidence sections for triage context.';
}

function resolveFullInvestigationSummary(overview, fallback, jiraSummary = '') {
  const candidates = [];
  const seen = new Set();

  function pushCandidate(value) {
    const text = normalizeNarrativeCandidate(value);
    if (!text || isPlaceholderNarrative(text) || seen.has(text)) {
      return;
    }
    seen.add(text);
    candidates.push(text);
  }

  pushCandidate(jiraSummary);
  pushCandidate(overview?.summary_full);
  pushCandidate(overview?.investigation_summary);
  pushCandidate(overview?.summary);
  pushCandidate(overview?.confidence_rationale);
  pushCandidate(overview?.evidence_summary);

  const journal = Array.isArray(overview?.triage_journal) ? overview.triage_journal : [];
  for (let idx = journal.length - 1; idx >= 0; idx -= 1) {
    const step = journal[idx];
    pushCandidate(step?.action);
    pushCandidate(step?.summary);
    pushCandidate(extractNarrativeFromFinding(step?.finding));
  }

  if (fallback) {
    pushCandidate(fallback);
  }

  return candidates[0] || String(fallback || '').trim();
}

function buildSummaryPreview(text, maxChars = 340) {
  const normalized = String(text || '').replace(/\s+/g, ' ').trim();
  if (!normalized) {
    return { text: '', truncated: false };
  }
  if (normalized.length <= maxChars) {
    return { text: normalized, truncated: false };
  }
  return { text: `${normalized.slice(0, maxChars).trimEnd()}...`, truncated: true };
}

export default function CaseDetailPage() {
  const { ticketId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState('overview');
  const [showInvestigation, setShowInvestigation] = useState(false);
  const [selectedAuditNode, setSelectedAuditNode] = useState(null);
  const [commentAuthor, setCommentAuthor] = useState('analyst');
  const [commentBody, setCommentBody] = useState('');
  const [saveMsg, setSaveMsg] = useState('');
  const [showSummaryModal, setShowSummaryModal] = useState(false);
  const [selectedTimelineEvent, setSelectedTimelineEvent] = useState(null);

  const ticketQuery = useQuery({
    queryKey: ['ticket', ticketId],
    queryFn: () => api.getTicket(ticketId),
    enabled: Boolean(ticketId),
    refetchInterval: 8000,
  });

  const auditQuery = useQuery({
    queryKey: ['ticket-audit', ticketId],
    queryFn: () => api.getAudit(ticketId),
    enabled: Boolean(ticketId) && activeTab === 'audit',
    refetchInterval: activeTab === 'audit' ? 10000 : false,
  });

  const updateMutation = useMutation({
    mutationFn: (payload) => api.updateTicket(ticketId, payload),
    onSuccess: async () => {
      setSaveMsg('Ticket saved.');
      await queryClient.invalidateQueries({ queryKey: ['ticket', ticketId] });
      await queryClient.invalidateQueries({ queryKey: ['tickets'] });
    },
    onError: (error) => {
      setSaveMsg(error.message || 'Failed to save ticket');
    },
  });

  const commentMutation = useMutation({
    mutationFn: (payload) => api.addComment(ticketId, payload),
    onSuccess: async () => {
      setCommentBody('');
      await queryClient.invalidateQueries({ queryKey: ['ticket', ticketId] });
    },
  });

  const ticket = ticketQuery.data?.ticket;
  const overview = ticketQuery.data?.case_overview || {};
  const comments = ticketQuery.data?.comments || [];
  const activities = ticketQuery.data?.activities || [];
  const runHealth = ticketQuery.data?.run_health || {};
  const jiraPayload = ticketQuery.data?.jira_payload || {};
  const auditNodes = useMemo(() => auditQuery.data?.graph?.nodes || [], [auditQuery.data]);

  if (ticketQuery.isLoading) {
    return <div className="card panel">Loading case...</div>;
  }

  if (!ticket) {
    return <div className="card panel">Case not found.</div>;
  }

  const iocs = Array.isArray(overview.iocs) ? overview.iocs : [];
  const events = Array.isArray(overview.events) ? overview.events : [];
  const assetContext = overview.asset_context || {};
  const alertDetails = overview.alert_details || {};
  const alertTags = Array.isArray(alertDetails.tags) ? alertDetails.tags : [];
  const alertedUser = assetContext.alerted_user || assetContext.user_name || assetContext.user || null;
  const pipelineScore = Number.isFinite(Number(overview.pipeline_score)) ? Math.round(Number(overview.pipeline_score)) : null;
  const runtimeSeconds = Number.isFinite(Number(overview.pipeline_runtime_seconds)) ? Number(overview.pipeline_runtime_seconds) : null;
  const confidenceMeta = overview.pipeline_confidence || {};
  const jiraSummary = extractInvestigationSummaryFromJiraDescription(jiraPayload?.description);
  const triageAction = overview.action || ticket.action || ticket.verdict || 'pending';
  const evidenceSummary = resolveEvidenceSummary(overview);
  const investigationSummary = extractFallbackSummary(overview, jiraSummary);
  const fullInvestigationSummary = resolveFullInvestigationSummary(overview, investigationSummary, jiraSummary);
  const summaryPreview = buildSummaryPreview(investigationSummary);
  const canExpandSummary = Boolean(fullInvestigationSummary)
    && (summaryPreview.truncated || fullInvestigationSummary.length > summaryPreview.text.length);
  const displayRiskScoreRaw = extractNumericScore(overview?.decision_risk_score)
    ?? extractNumericScore(overview?.risk_score)
    ?? extractNumericScore(jiraPayload?.risk_score)
    ?? extractNumericScore(overview?.pipeline_score)
    ?? extractNumericScore(ticket?.risk_score);
  const displayRiskScore = Number.isFinite(Number(displayRiskScoreRaw)) ? Number(displayRiskScoreRaw) : null;
  const displayRiskScoreLabel = displayRiskScore == null
    ? '—'
    : (Number.isInteger(displayRiskScore) ? String(displayRiskScore) : displayRiskScore.toFixed(1));
  const displaySeverity = severityFromRiskScore(
    displayRiskScore,
    overview?.effective_severity || ticket?.effective_severity || ticket?.severity,
  );
  const displayRiskTone = riskTone(displayRiskScore);
  const confidenceScore = extractNumericScore(overview?.decision_confidence_score)
    ?? extractNumericScore(overview?.confidence_score)
    ?? null;
  const panelOverview = { ...overview, summary: investigationSummary, evidence_summary: evidenceSummary };

  function onSaveAction(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    updateMutation.mutate({
      status: form.get('status') || ticket.status,
      classification: form.get('classification') || null,
      verdict: form.get('verdict') || null,
      close_note: form.get('close_note') || null,
    });
  }

  function addComment(event) {
    event.preventDefault();
    if (!commentBody.trim()) {
      return;
    }
    commentMutation.mutate({ author: commentAuthor || 'analyst', body: commentBody.trim() });
  }

  return (
    <section className="case-detail-page">
      <div className="case-detail-main">
        <div className="case-header">
          <button type="button" className="btn btn-ghost" onClick={() => navigate('/cases')}>
            <ArrowLeft size={14} /> Back
          </button>
          <div className="case-title-wrap">
            <div className="case-title-meta">
              <span className="mono">{ticket.ticket_key}</span>
              <span className={severityClass(displaySeverity)}>{severityLabel(displaySeverity)}</span>
              <span className={statusClass(ticket.status)}>{statusLabel(ticket.status)}</span>
            </div>
            <h1>{asInlineText(ticket.title, 'Untitled Case')}</h1>
            <p>{severityLabel(displaySeverity)} severity | created {shortDate(ticket.created_at)}</p>
          </div>
          {overview?.triage_journal?.length > 0 && (
            <button type="button" className="btn btn-ghost" onClick={() => setShowInvestigation((prev) => !prev)}>
              <Bot size={14} /> AI Steps
            </button>
          )}
        </div>

        <div className="tabs">
          <button type="button" className={activeTab === 'overview' ? 'active' : ''} onClick={() => setActiveTab('overview')}>
            Overview
          </button>
          <button type="button" className={activeTab === 'audit' ? 'active' : ''} onClick={() => setActiveTab('audit')}>
            LLM Auditability
          </button>
        </div>

        {activeTab === 'overview' && (
          <div className="overview-grid">
            <article className="card panel triage-result">
              <div className="triage-bot"><Bot size={18} /></div>
              <div className="triage-left">
                <div className="triage-meta-row">
                  <div className="triage-label">AI TRIAGE RESULT</div>
                  <div className="triage-headline">{asInlineText(overview.classification || ticket.classification || 'unclassified', 'unclassified')}</div>
                  <span className={actionClass(triageAction)}>Action: {actionLabel(triageAction)}</span>
                  {runtimeSeconds != null && (
                    <span className="triage-runtime">
                      <Clock size={12} /> {runtimeSeconds.toFixed(1)}s
                    </span>
                  )}
                  {confidenceScore != null && (
                    <span className="confidence-pill">Confidence {confidenceScore.toFixed(1)}%</span>
                  )}
                </div>
                <div className="triage-summary">
                  <p>{summaryPreview.text || investigationSummary}</p>
                  {canExpandSummary && (
                    <button type="button" className="summary-see-all" onClick={() => setShowSummaryModal(true)}>
                      See all
                    </button>
                  )}
                </div>
              </div>
              <div className="score-block">
                <div className={`score-ring risk-${displayRiskTone}`}><span>{displayRiskScoreLabel}</span></div>
                <div className="score-cap">TRIAGE SCORE</div>
                <div className={`score-text risk-${displayRiskTone}`}>{displayRiskScore == null ? 'Unavailable' : confidenceLabel(displayRiskScore)}</div>
              </div>
            </article>

            <article className="card panel">
              <header className="panel-head"><h2>Host Context</h2></header>
              <div className="asset-grid">
                <div className="detail-cell">
                  <span>Host Device</span>
                  <strong>{asInlineText(assetContext.host_name, '—')}</strong>
                </div>
                <div className="detail-cell">
                  <span>Host IP Address</span>
                  <strong>{asInlineText(assetContext.host_ip, '—')}</strong>
                </div>
                <div className="detail-cell">
                  <span>Device Type</span>
                  <strong>{asInlineText(assetContext.device_type, '—')}</strong>
                </div>
                <div className="detail-cell">
                  <span>Alerted User</span>
                  <strong>{asInlineText(alertedUser, '—')}</strong>
                </div>
                <div className="detail-cell">
                  <span>Operating System</span>
                  <strong>{asInlineText(assetContext.os_name || assetContext.os_platform, '—')}</strong>
                </div>
              </div>
            </article>

            <article className="card panel">
              <header className="panel-head"><h2>Indicators Of Compromise · {iocs.length}</h2></header>
              <div className="ioc-panel-content">
                {!iocs.length && <div className="empty-state">No high-signal IOC artifacts extracted yet.</div>}
                {!!iocs.length && (
                  <div className="ioc-chip-row">
                    {iocs.map((ioc, index) => (
                      <IOCChip key={`${ioc.type || 'ioc'}:${ioc.value || 'value'}:${index}`} ioc={ioc} />
                    ))}
                  </div>
                )}
              </div>
            </article>

            <article className="card panel">
              <header className="panel-head"><h2>Alert Details</h2></header>
              <div className="details-grid">
                <div className="detail-cell"><span>Source</span><strong>{asInlineText(alertDetails.source, 'siem')}</strong></div>
                <div className="detail-cell"><span>Assignee</span><strong>{asInlineText(alertDetails.assignee, '—')}</strong></div>
                <div className="detail-cell"><span>Created</span><strong>{shortDate(alertDetails.created_at || ticket.created_at)}</strong></div>
              </div>
              <div className="alert-description">{asInlineText(alertDetails.description || ticket.summary || ticket.title, 'No alert description available.')}</div>
              {!!alertTags.length && (
                <div className="alert-tag-list">
                  {alertTags.map((tag, idx) => (
                    <span key={`${tag}-${idx}`} className="alert-tag">{tag}</span>
                  ))}
                </div>
              )}
            </article>

            <article className="card panel">
              <header className="panel-head"><h2>Incident Timeline</h2></header>
              {!!events.length && (
                <div className="timeline-list">
                  {events.map((event, index) => (
                    <article key={`${event.event || 'event'}-${event.timestamp || 'ts'}-${index}`} className="timeline-item">
                      <div className="timeline-rail">
                        <span className="timeline-dot" />
                      </div>
                      <button
                        type="button"
                        className="timeline-body timeline-open"
                        onClick={() => setSelectedTimelineEvent(event)}
                      >
                        <div className="timeline-head">
                          <span className="mono timeline-time">{shortDate(event.timestamp)}</span>
                          <div className="timeline-head-right">
                            <span className={`timeline-tag timeline-${String(event.category || 'info').toLowerCase()}`}>
                              {asInlineText(event.event, 'Observed Event')}
                            </span>
                            {Number(event.duplicate_count || 1) > 1 && (
                              <span className="timeline-dup">x{Number(event.duplicate_count)}</span>
                            )}
                          </div>
                        </div>
                        {event.host && (
                          <div className="timeline-meta">Host: {asInlineText(event.host, '—')}</div>
                        )}
                        <p className="timeline-detail">{asInlineText(event.description, '')}</p>
                      </button>
                    </article>
                  ))}
                </div>
              )}
              {!events.length && (
                <div className="empty-state">No evidence events captured for this case yet.</div>
              )}
            </article>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="audit-grid">
            <article className="card panel">
              <header className="panel-head">
                <h2><Network size={14} /> Agent Execution Graph</h2>
                <span className="mono sub-pill">{auditNodes.length} nodes</span>
              </header>
              <div className="audit-canvas">
                <AuditGraph nodes={auditNodes} selectedNode={selectedAuditNode} onNodeSelect={setSelectedAuditNode} />
              </div>
            </article>

            <article className="card panel">
              <header className="panel-head"><h2>Node Details</h2></header>
              {!selectedAuditNode && <div className="empty-state">Select a node.</div>}
              {selectedAuditNode && (
                <div className="node-detail">
                  <h3>{asInlineText(selectedAuditNode.name || selectedAuditNode.label, 'Node')}</h3>
                  <div className="node-detail-grid">
                    <div>
                      <h4>Input</h4>
                      <pre>{asBlockText(selectedAuditNode.input_data, '-')}</pre>
                    </div>
                    <div>
                      <h4>Output</h4>
                      <pre>{asBlockText(selectedAuditNode.output_data, '-')}</pre>
                    </div>
                  </div>
                </div>
              )}
            </article>
          </div>
        )}
      </div>

      <aside className="case-side">
        <article className="card panel">
          <header className="panel-head"><h2>Analyst Actions</h2></header>
          <form className="ticket-grid" onSubmit={onSaveAction}>
            <label>
              Ticket Status
              <select name="status" defaultValue={ticket.status || 'to_do'}>
                {STATUS_OPTIONS.map((status) => (
                  <option key={status} value={status}>{statusLabel(status)}</option>
                ))}
              </select>
            </label>
            <label>
              Classification
              <select name="classification" defaultValue={ticket.classification || ''}>
                <option value="">Select classification</option>
                <option value="benign">Benign</option>
                <option value="suspicious">Suspicious</option>
                <option value="malicious">Malicious</option>
                <option value="false_positive">False Positive</option>
              </select>
            </label>
            <label>
              Verdict
              <select name="verdict" defaultValue={ticket.verdict || ''}>
                <option value="">Select verdict</option>
                <option value="close">Close</option>
                <option value="escalate_to_ir">Escalate to IR</option>
                <option value="block_asset_user">Block Asset/User</option>
                <option value="monitor">Monitor</option>
              </select>
            </label>
            <label>
              Close Note
              <textarea name="close_note" rows={8} defaultValue={ticket.close_note || ''} placeholder="Analyst close note for this alert..." />
            </label>
            <div className="row-actions">
              <button type="submit" className="btn btn-primary" disabled={updateMutation.isPending}>{updateMutation.isPending ? 'Saving...' : 'Save Ticket'}</button>
              {saveMsg && <span className="inline-msg">{saveMsg}</span>}
            </div>
            {ticket?.id && <Link className="btn btn-ghost" to={`/api/tickets/${ticket.id}/case/download`}>Download Case</Link>}
            <div className="jira-preview">
              <h3>Jira Sync Preview</h3>
              <div className="jira-row"><span>Issue</span><strong>{asInlineText(jiraPayload.issue_key || ticket.ticket_key, ticket.ticket_key)}</strong></div>
              <div className="jira-row"><span>Status</span><strong>{asInlineText(jiraPayload.status || statusLabel(ticket.status), statusLabel(ticket.status))}</strong></div>
              <div className="jira-row"><span>Classification</span><strong>{asInlineText(jiraPayload.classification, '—')}</strong></div>
              <div className="jira-row"><span>Verdict</span><strong>{asInlineText(jiraPayload.verdict, '—')}</strong></div>
              <div className="jira-row"><span>Risk Score</span><strong>{displayRiskScoreLabel}</strong></div>
              <div className="jira-description">{asInlineText(jiraPayload.description, 'No Jira description available.')}</div>
            </div>
          </form>
        </article>

        <article className="card panel">
          <header className="panel-head"><h2>Analyst Comments</h2></header>
          <div className="comment-list">
            {!comments.length && <div className="empty-state">No comments yet.</div>}
            {comments.map((comment) => (
              <article key={comment.id} className="comment-item">
                <div className="meta"><span>{asInlineText(comment.author, 'analyst')}</span><span>{shortDate(comment.created_at)}</span></div>
                <div>{asInlineText(comment.body, '')}</div>
              </article>
            ))}
          </div>
          <form className="comment-editor" onSubmit={addComment}>
            <input value={commentAuthor} onChange={(event) => setCommentAuthor(event.target.value)} placeholder="author" />
            <textarea value={commentBody} onChange={(event) => setCommentBody(event.target.value)} rows={4} placeholder="Add a ticket comment..." />
            <button type="submit" className="btn btn-primary" disabled={commentMutation.isPending || !commentBody.trim()}>
              {commentMutation.isPending ? 'Adding...' : 'Add Comment'}
            </button>
          </form>
        </article>

        <article className="card panel">
          <header className="panel-head"><h2>Activity</h2></header>
          <ul className="activity-list">
            {!activities.length && <li>No activity yet.</li>}
            {activities.slice(-60).map((item) => (
              <li key={item.id}>
                <strong>{asInlineText(item.event_type, 'event')}</strong>
                <span>{shortDate(item.created_at)}</span>
                <pre>{asBlockText(item.details, '{}')}</pre>
              </li>
            ))}
          </ul>
        </article>

        <article className="card panel">
          <header className="panel-head"><h2>Pipeline Health</h2></header>
          {!runHealth?.available && <div className="empty-state">Run data not available.</div>}
          {runHealth?.available && (
            <div className="status-grid">
              <div><span>Run ID</span><strong className="mono truncate">{asInlineText(runHealth.run_id, '-')}</strong></div>
              <div><span>Waves</span><strong>{asInlineText(runHealth.waves, '0')}</strong></div>
              <div><span>Actions</span><strong>{asInlineText(runHealth.total_actions, '0')}</strong></div>
              <div><span>Success Rate</span><strong>{asInlineText(runHealth.success_rate, '0')}%</strong></div>
              <div><span>Failures</span><strong>{runHealth.has_failures ? 'Yes' : 'No'}</strong></div>
            </div>
          )}
        </article>
      </aside>

      {showInvestigation && <InvestigationPanel caseOverview={panelOverview} onClose={() => setShowInvestigation(false)} />}
      {showSummaryModal && (
        <div className="summary-modal-backdrop" role="presentation" onClick={() => setShowSummaryModal(false)}>
          <article className="summary-modal card panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <header className="panel-head">
              <h2>Full Investigation Summary</h2>
              <button type="button" className="btn btn-ghost" onClick={() => setShowSummaryModal(false)}>Close</button>
            </header>
            <div className="summary-modal-body">
              <p>{fullInvestigationSummary || investigationSummary}</p>
            </div>
          </article>
        </div>
      )}
      {selectedTimelineEvent && (
        <div className="summary-modal-backdrop" role="presentation" onClick={() => setSelectedTimelineEvent(null)}>
          <article className="summary-modal card panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <header className="panel-head">
              <h2>{asInlineText(selectedTimelineEvent.event, 'Incident Event')}</h2>
              <button type="button" className="btn btn-ghost" onClick={() => setSelectedTimelineEvent(null)}>Close</button>
            </header>
            <div className="summary-modal-body">
              <p><strong>Time:</strong> {shortDate(selectedTimelineEvent.timestamp)}</p>
              <p><strong>Host:</strong> {asInlineText(selectedTimelineEvent.host, '—')}</p>
              <p><strong>Event:</strong> {asInlineText(selectedTimelineEvent.event, 'Observed Event')}</p>
              <p><strong>Details:</strong> {asInlineText(selectedTimelineEvent.full_detail || selectedTimelineEvent.description, 'No details available.')}</p>
              {Array.isArray(selectedTimelineEvent.samples) && selectedTimelineEvent.samples.length > 0 && (
                <div className="timeline-sample-list">
                  <p><strong>Event Contents</strong></p>
                  {selectedTimelineEvent.samples.map((sample, index) => (
                    <pre key={`${index}-${sample.slice(0, 32)}`} className="timeline-sample-pre">{sample}</pre>
                  ))}
                </div>
              )}
              {Number(selectedTimelineEvent.duplicate_count || 1) > 1 && (
                <p><strong>Occurrences:</strong> {Number(selectedTimelineEvent.duplicate_count)}</p>
              )}
            </div>
          </article>
        </div>
      )}
    </section>
  );
}
