import { useState } from 'react';
import { Bot, CheckCircle, ChevronDown, ChevronRight, Clock, Database, Globe, Search, Shield } from 'lucide-react';

const AGENT_ICONS = {
  IntakeAgent: Shield,
  SOCAnalystOrchestrator: Database,
  ioc_enrichment_specialist: Globe,
  osint_specialist: Search,
  siem_specialist: Database,
  timeline_specialist: Clock,
  SOC2DecisionAgent: CheckCircle,
};

function pickIcon(agent) {
  const text = String(agent || '');
  for (const key of Object.keys(AGENT_ICONS)) {
    if (text.includes(key)) {
      return AGENT_ICONS[key];
    }
  }
  return Bot;
}

function StepRow({ step, index }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = pickIcon(step.agent);
  const findingText = typeof step.finding === 'string' ? step.finding : JSON.stringify(step.finding, null, 2);

  return (
    <article className={`journal-step${expanded ? ' expanded' : ''}`}>
      <button type="button" className="journal-step-head" onClick={() => setExpanded((prev) => !prev)}>
        <span className="journal-index">{String(index + 1).padStart(2, '0')}</span>
        <span className="journal-icon"><Icon size={12} /></span>
        <span className="journal-main">
          <span className="journal-agent">{step.agent || 'Agent'}</span>
          <span className="journal-action">{step.action || 'Recorded step'}</span>
        </span>
        <span className="journal-time">{step.timestamp || ''}</span>
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {expanded && step.finding && (
        <pre className="journal-finding">{findingText}</pre>
      )}
    </article>
  );
}

export default function InvestigationPanel({ caseOverview, onClose }) {
  const journal = Array.isArray(caseOverview?.triage_journal) ? caseOverview.triage_journal : [];
  const summary = String(caseOverview?.summary || '').trim();

  return (
    <aside className="investigation-drawer">
      <header className="drawer-head">
        <div className="drawer-title-wrap">
          <span className="drawer-icon"><Bot size={14} /></span>
          <div>
            <h3>AI Investigation Steps</h3>
            <p>{journal.length} steps recorded</p>
          </div>
        </div>
        <button type="button" className="btn btn-ghost" onClick={onClose}>Close</button>
      </header>

      {summary && (
        <section className="drawer-summary">
          <h4>Agent Summary</h4>
          <p>{summary}</p>
        </section>
      )}

      <section className="drawer-steps">
        {!journal.length && <div className="empty-state">No investigation steps recorded.</div>}
        {journal.map((step, index) => (
          <StepRow key={`${step.agent || 'step'}-${index}`} step={step} index={index} />
        ))}
      </section>
    </aside>
  );
}
