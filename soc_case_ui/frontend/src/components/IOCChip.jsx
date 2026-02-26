import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, FileText, Globe, Hash, Link, Terminal } from 'lucide-react';
import { normalizeToolLabel } from '../api/client';

const TYPE_CONFIG = {
  ip: { icon: Globe, label: 'IP Address', colorClass: 'ioc-chip ip' },
  domain: { icon: Globe, label: 'Domain', colorClass: 'ioc-chip domain' },
  url: { icon: Link, label: 'URL', colorClass: 'ioc-chip url' },
  hash: { icon: Hash, label: 'Hash', colorClass: 'ioc-chip hash' },
  file: { icon: FileText, label: 'Script/File', colorClass: 'ioc-chip file' },
  command: { icon: Terminal, label: 'Command Line', colorClass: 'ioc-chip command' },
  default: { icon: AlertTriangle, label: 'IOC', colorClass: 'ioc-chip' },
};

function scoreColor(score) {
  if (score == null) return 'score-muted';
  if (score >= 80) return 'score-high';
  if (score >= 60) return 'score-medhigh';
  if (score >= 40) return 'score-medium';
  return 'score-low';
}

export default function IOCChip({ ioc }) {
  const [open, setOpen] = useState(false);
  const [alignRight, setAlignRight] = useState(false);
  const chipRef = useRef(null);
  const config = TYPE_CONFIG[ioc?.type] || TYPE_CONFIG.default;
  const Icon = config.icon;
  const vtVerdict = String(ioc?.virustotal_verdict || '').toLowerCase();
  const hasVT = Boolean(ioc?.virustotal_checked);
  const vtEligible = ['ip', 'domain', 'url', 'hash', 'file'].includes(String(ioc?.type || '').toLowerCase());
  const vtLabel = vtVerdict ? vtVerdict.toUpperCase() : 'UNKNOWN';
  const vtStats = ioc?.virustotal_stats || null;
  const filePath = String(ioc?.path || ioc?.file_path || ioc?.value || '').trim();
  const displayValue = String(ioc?.display_value || ioc?.value || '-').trim() || '-';
  const contextText = String(ioc?.context || '').trim();

  useEffect(() => {
    if (!open || !chipRef.current || typeof window === 'undefined') return;
    const rect = chipRef.current.getBoundingClientRect();
    const estimatedWidth = 360;
    setAlignRight(rect.left + estimatedWidth > window.innerWidth - 20);
  }, [open]);

  return (
    <div className="ioc-chip-item" ref={chipRef}>
      <button type="button" className={config.colorClass} onClick={() => setOpen((prev) => !prev)}>
        <Icon size={12} />
        <span className="chip-value">{displayValue}</span>
        {ioc?.threat_score != null && <span className={scoreColor(ioc.threat_score)}>{ioc.threat_score}</span>}
      </button>

      {open && (
        <div className={`ioc-popover ${alignRight ? 'align-right' : ''}`}>
          <div className="ioc-pop-head">
            <strong>{config.label}</strong>
            <button type="button" onClick={() => setOpen(false)}>x</button>
          </div>
          <div className="ioc-pop-value">{displayValue}</div>
          {ioc?.threat_score != null && (
            <div className="ioc-pop-line">
              Threat Score: <span className={scoreColor(ioc.threat_score)}>{ioc.threat_score}/100</span>
            </div>
          )}
          {vtEligible && (
            <div className="ioc-pop-line">
              VirusTotal Verdict:{' '}
              <span className={`vt-verdict vt-${hasVT ? (vtVerdict || 'unknown') : 'unknown'}`}>
                {hasVT ? vtLabel : 'NOT CHECKED'}
              </span>
            </div>
          )}
          {hasVT && vtStats && (
            <div className="ioc-pop-line">
              VirusTotal Stats: {vtStats.malicious ?? 0} malicious, {vtStats.suspicious ?? 0} suspicious, {vtStats.harmless ?? 0} harmless
            </div>
          )}
          {String(ioc?.type || '').toLowerCase() === 'file' && (
            <div className="ioc-pop-line">Path: {filePath || '-'}</div>
          )}
          {contextText && <div className="ioc-pop-line">Context: {contextText}</div>}
          {ioc?.evidence && <div className="ioc-pop-line">Evidence: {ioc.evidence}</div>}
          {ioc?.source && <div className="ioc-pop-line">Intel Source: {ioc.source}</div>}
          {ioc?.source_tool && <div className="ioc-pop-line">Source: {normalizeToolLabel(ioc.source_tool)}</div>}
        </div>
      )}
    </div>
  );
}
