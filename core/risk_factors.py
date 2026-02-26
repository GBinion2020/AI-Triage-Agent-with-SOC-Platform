from typing import List, Dict, Any
import json
import re
from schemas.state import InvestigationState
from core.scoring import RiskScoringMatrix

CATEGORY_DISPLAY = {
    "threat_intel": "Threat Intelligence",
    "behavior": "Baseline & Behavioral Deviation",
    "mitre": "MITRE ATT&CK Alignment",
    "process": "Process & Execution Signals",
    "identity": "Privilege & Identity Indicators",
    "network": "Network Indicators",
    "detection": "Detection Logic Confidence",
}

def _add_factor(
    factors: List[Dict[str, Any]],
    category: str,
    weight_type: str,
    confidence: float,
    evidence: str,
) -> None:
    factors.append(
        {
            "category": category,
            "type": weight_type,
            "confidence": confidence,
            "evidence": evidence,
        }
    )


def _load_evidence_payload(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    if not ((raw.startswith("{") and raw.endswith("}")) or (raw.startswith("[") and raw.endswith("]"))):
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_vt_stats(text: str) -> Dict[str, Any]:
    verdict_match = re.search(r"Verdict:\s*([A-Za-z_/\- ]+)", text, flags=re.IGNORECASE)
    stats_match = re.search(
        r"Stats:\s*(\d+)\s+malicious,\s*(\d+)\s+suspicious",
        text,
        flags=re.IGNORECASE,
    )
    indicator_match = re.search(r"VirusTotal\s+(IP|DOMAIN|HASH):\s*([^\s,\n]+)", text, flags=re.IGNORECASE)
    if not verdict_match and not stats_match and not indicator_match:
        return {}
    return {
        "verdict": (verdict_match.group(1).strip().lower() if verdict_match else ""),
        "malicious": int(stats_match.group(1)) if stats_match else 0,
        "suspicious": int(stats_match.group(2)) if stats_match else 0,
        "indicator_type": (indicator_match.group(1).lower() if indicator_match else "indicator"),
        "indicator_value": (indicator_match.group(2).strip() if indicator_match else "unknown"),
    }


def _collect_siem_text_blocks(state: InvestigationState) -> List[str]:
    blocks: List[str] = []
    for ev in state.evidence:
        source = str(ev.source_tool or "").lower()
        if "siem" not in source:
            continue

        if ev.summary:
            blocks.append(str(ev.summary))
        if ev.content:
            blocks.append(str(ev.content))

        payload = _load_evidence_payload(ev.content)
        if payload:
            for finding in payload.get("findings", []) if isinstance(payload.get("findings"), list) else []:
                if not isinstance(finding, dict):
                    continue
                title = str(finding.get("title") or "").strip()
                detail = str(finding.get("detail") or "").strip()
                joined = f"{title}: {detail}".strip(": ")
                if joined:
                    blocks.append(joined)
    return blocks

def build_risk_factors(state: InvestigationState) -> List[Dict[str, Any]]:
    """
    Deterministically derive risk factors from alert signals and tool evidence.
    """
    factors: List[Dict[str, Any]] = []
    signals = state.alert.analysis_signals

    # Threat Intelligence (VirusTotal, IP reputation signals)
    for ev in state.evidence:
        source_tool = str(ev.source_tool or "").lower()
        if "virustotal" not in source_tool and source_tool != "check_virustotal":
            continue

        candidate_text = "\n".join(
            [
                str(ev.summary or ""),
                str(ev.content or ""),
            ]
        )
        stats = _extract_vt_stats(candidate_text)
        if not stats:
            payload = _load_evidence_payload(ev.content)
            if payload:
                findings = payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    finding_stats = _extract_vt_stats(str(finding.get("detail") or ""))
                    if finding_stats:
                        stats = finding_stats
                        break
        if not stats:
            continue

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        indicator_type = str(stats.get("indicator_type") or "indicator")
        indicator_value = str(stats.get("indicator_value") or "unknown")

        if malicious > 0:
            weight_type = "known_malicious_hash" if indicator_type == "hash" else "known_c2"
            _add_factor(
                factors,
                "threat_intel",
                weight_type,
                1.0,
                f"VirusTotal {indicator_type} {indicator_value} flagged malicious ({malicious} detections).",
            )
        elif suspicious > 0:
            _add_factor(
                factors,
                "threat_intel",
                "medium_risk_hit",
                0.6,
                f"VirusTotal {indicator_type} {indicator_value} flagged suspicious ({suspicious} detections).",
            )

    if signals.ip_reputation_risk:
        _add_factor(
            factors,
            "threat_intel",
            "low_risk_hit",
            0.5,
                "Alert signals flagged low-confidence IP reputation risk.",
            )

    # SIEM contextual enrichment from surrounding host activity.
    siem_blocks = _collect_siem_text_blocks(state)
    if siem_blocks:
        joined = "\n".join(siem_blocks)
        lowered = joined.lower()

        remote_cmd_count = len(
            re.findall(r"(execute a remote command|scriptblock id|provider lifecycle)", lowered)
        )
        red_team_markers = {
            marker
            for marker in (
                "stop-executionlog",
                "invoke-atomictest",
                "atomicredteam",
                "atomic red team",
            )
            if marker in lowered
        }
        suspicious_command_markers = {
            marker
            for marker in (
                "invoke-webrequest",
                "disablekeepalive",
                "method post",
                "data staging",
                "archive created",
                "line numbers",
            )
            if marker in lowered
        }
        high_risk_markers = {
            marker
            for marker in (
                "mimikatz",
                "sekurlsa",
                "lsass",
                "credential dump",
                "rundll32 comsvcs.dll",
                "vss deletion",
                "delete shadows",
            )
            if marker in lowered
        }

        if remote_cmd_count >= 5:
            _add_factor(
                factors,
                "process",
                "rare_process",
                0.2,
                f"SIEM surrounding logs include repeated remote/scripted PowerShell activity ({remote_cmd_count} events) around alert time.",
            )

        if red_team_markers:
            _add_factor(
                factors,
                "behavior",
                "minor_deviation",
                0.4,
                "SIEM telemetry contains automation/red-team style execution markers "
                f"({', '.join(sorted(red_team_markers))}).",
            )

        if len(suspicious_command_markers) >= 2:
            _add_factor(
                factors,
                "network",
                "unusual_outbound",
                0.3,
                "SIEM evidence includes scripted outbound command markers "
                f"({', '.join(sorted(suspicious_command_markers))}).",
            )

        if high_risk_markers:
            _add_factor(
                factors,
                "process",
                "suspicious_parent_child",
                0.8,
                "High-risk host indicators observed in SIEM surrounding logs "
                f"({', '.join(sorted(high_risk_markers))}).",
            )

    # Behavioral Baseline Deviation
    if signals.impossible_travel or signals.new_country_login:
        _add_factor(
            factors,
            "behavior",
            "severe_deviation",
            0.9,
            "Identity telemetry indicates impossible travel or new-country login.",
        )
    elif signals.behavioral_baseline_deviation or signals.sudden_access_spike or signals.role_behavior_mismatch:
        _add_factor(
            factors,
            "behavior",
            "moderate_deviation",
            0.7,
            "Behavior deviates from baseline (access spike or role mismatch).",
        )
    elif signals.time_of_day_anomaly or signals.new_tool_usage or signals.copy_paste_bulk_activity:
        _add_factor(
            factors,
            "behavior",
            "minor_deviation",
            0.5,
            "Minor behavioral anomaly detected (time-of-day or new tool usage).",
        )

    # MITRE ATT&CK Alignment
    technique_count = len(state.alert.detection.mitre_techniques or [])
    if technique_count >= 2:
        _add_factor(
            factors,
            "mitre",
            "multi_step_chain",
            0.8,
            f"Multiple ATT&CK techniques mapped ({technique_count} techniques).",
        )
    elif technique_count == 1:
        _add_factor(
            factors,
            "mitre",
            "medium_risk_ttp",
            0.6,
            "Single ATT&CK technique mapped from the alert.",
        )

    # Process & Execution Signals
    if (
        signals.process_injection_behavior
        or signals.parent_process_mismatch
        or signals.child_process_anomaly
        or signals.process_hollowing_pattern
    ):
        _add_factor(
            factors,
            "process",
            "suspicious_parent_child",
            0.8,
            "Process lineage or injection behavior flagged in telemetry.",
        )
    if (
        signals.execution_from_temp
        or signals.execution_from_user_writeable_dir
        or signals.unexpected_interpreter
    ):
        _add_factor(
            factors,
            "process",
            "rare_process",
            0.6,
            "Execution context indicates rare or user-writable origin.",
        )

    # Identity & Privilege Indicators
    if signals.privilege_escalation:
        _add_factor(
            factors,
            "identity",
            "privilege_escalation",
            1.0,
            "Privilege escalation signal triggered in alert telemetry.",
        )
    if signals.role_assignment_anomaly or signals.service_account_misuse:
        _add_factor(
            factors,
            "identity",
            "admin_anomaly",
            0.8,
            "Admin or service account behavior deviates from expected role.",
        )
    if (
        signals.new_device_login
        or signals.mfa_bypass_suspected
        or signals.password_spray_pattern
        or signals.token_replay_detected
        or signals.auth_after_disable
    ):
        _add_factor(
            factors,
            "identity",
            "auth_pattern_anomaly",
            0.7,
            "Authentication telemetry shows anomalous patterns.",
        )

    # Network Indicators
    if signals.low_and_slow_exfiltration or signals.archive_before_exfil or signals.data_compression_detected:
        _add_factor(
            factors,
            "network",
            "exfiltration_pattern",
            0.9,
            "Telemetry indicates data staging or exfiltration patterns.",
        )
    if (
        signals.external_communication
        or signals.rare_destination
        or signals.new_destination_for_host
        or signals.beaconing_pattern
        or signals.dns_tunneling_suspected
        or signals.user_agent_anomaly
    ):
        _add_factor(
            factors,
            "network",
            "unusual_outbound",
            0.7,
            "Outbound network activity is unusual or indicative of C2.",
        )

    # Detection Logic Confidence
    confidence_tags = [t.lower() for t in (state.alert.detection.confidence_tags or [])]
    rule_type = (state.alert.detection.rule_type or "").lower()
    if "high" in confidence_tags or "high_confidence" in confidence_tags:
        _add_factor(
            factors,
            "detection",
            "high_confidence_detection",
            0.9,
            "Detection metadata indicates high-confidence logic.",
        )
    elif "medium" in confidence_tags:
        _add_factor(
            factors,
            "detection",
            "medium_confidence_detection",
            0.7,
            "Detection metadata indicates medium-confidence logic.",
        )
    elif "low" in confidence_tags:
        _add_factor(
            factors,
            "detection",
            "low_confidence_detection",
            0.4,
            "Detection metadata indicates low-confidence logic.",
        )
    elif rule_type in ("behavioral", "ml"):
        _add_factor(
            factors,
            "detection",
            "high_confidence_detection",
            0.7,
            "Detection rule type is behavioral/ML.",
        )
    elif rule_type in ("query", "threshold"):
        _add_factor(
            factors,
            "detection",
            "medium_confidence_detection",
            0.6,
            "Detection rule type is heuristic or query-based.",
        )

    return factors

def build_evidence_table(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert risk factors into an evidence table with deterministic weights.
    """
    table: List[Dict[str, Any]] = []
    for factor in factors:
        category = factor["category"]
        weight_type = factor["type"]
        weight = RiskScoringMatrix.get_weight(category, weight_type)
        if weight is None:
            continue
        confidence = float(factor.get("confidence", 1.0))
        contribution = weight * confidence
        table.append(
            {
                "category": CATEGORY_DISPLAY.get(category, category),
                "evidence": factor.get("evidence", ""),
                "weight": weight,
                "confidence": confidence,
                "contribution": contribution,
            }
        )
    return table

def is_conclusive_score(score: float) -> bool:
    """
    Conclusive scores are outside the Suspicious band.
    """
    return score <= 20 or score >= 61
