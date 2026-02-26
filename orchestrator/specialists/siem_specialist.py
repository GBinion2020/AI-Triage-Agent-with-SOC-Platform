from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from pydantic import BaseModel, Field, ValidationError

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from mcp_server.formatter import normalize_tool_output
from mcp_server.tools import query_builder, siem
from orchestrator.json_utils import extract_json_object
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


class SIEMRequest(BaseModel):
    host_name: str
    alert_timestamp: str
    focus: List[str] = Field(default_factory=lambda: ["process", "network", "identity"])
    max_queries: int = Field(default=3, ge=1, le=6)
    indicators: List[str] = Field(default_factory=list)


class SIEMQueryChoice(BaseModel):
    query_type: str
    args: Dict[str, Any] = Field(default_factory=dict)
    stop: bool = False
    reason: str = ""


class SIEMSpecialist:
    NON_DOMAIN_SUFFIXES = {
        "ps",
        "ps1",
        "psm1",
        "bat",
        "cmd",
        "vbs",
        "js",
        "py",
        "sh",
        "txt",
        "log",
        "csv",
        "json",
        "xml",
        "yml",
        "yaml",
        "ini",
        "cfg",
        "conf",
        "zip",
        "rar",
        "7z",
        "exe",
        "dll",
        "sys",
        "doc",
        "docx",
        "pdf",
        "exception",
        "innerexception",
        "psmessagedetails",
        "scriptblock",
        "runspaceid",
        "psobject",
        "properties",
    }
    NON_DOMAIN_TOKENS = {
        "this",
        "exception",
        "innerexception",
        "psmessagedetails",
        "scriptblock",
        "runspaceid",
        "psobject",
        "properties",
    }

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.last_prompt: str = ""
        self.last_raw_response: str = ""
        self.last_error: str = ""

    def execute(
        self,
        action_id: str,
        request: Dict[str, Any],
        state: InvestigationState,
        card: ToolCard,
        policy_engine: PolicyEngine,
    ) -> ToolExecutionResult:
        start = time.time()

        try:
            req = SIEMRequest.model_validate(request)
        except ValidationError as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Invalid SIEM request schema: {exc}",
                request=request,
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        query_log: List[Dict[str, Any]] = []
        findings: List[EvidenceFinding] = []
        all_iocs: Dict[str, List[str]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "file": [],
            "command": [],
            "hash": [],
        }
        parsed_results: List[Dict[str, Any]] = []
        executed_queries: set[str] = set()

        for idx in range(req.max_queries):
            choice = self._choose_next_query(req, state, query_log, idx)
            if choice.stop:
                break

            run = self._run_query(choice, req, state, policy_engine, executed_queries)
            query_log.append(run)

            if run.get("status") != "success":
                continue

            normalized = run.get("normalized")
            if isinstance(normalized, dict):
                parsed_results.append(normalized)

                extracted = (normalized.get("extracted_entities") or {}).get("iocs") or {}
                for ioc_type in ("ip", "domain", "url", "file", "command", "hash"):
                    for value in extracted.get(ioc_type, []) or []:
                        if value and value not in all_iocs[ioc_type]:
                            all_iocs[ioc_type].append(value)

                for event in (normalized.get("key_events") or [])[:10]:
                    ts = event.get("timestamp") or event.get("@timestamp")
                    action = event.get("event_action") or "event"
                    msg = event.get("message") or ""
                    detail = msg if len(msg) < 240 else msg[:240] + "..."
                    findings.append(
                        EvidenceFinding(
                            title=f"{action}",
                            detail=detail,
                            severity="info",
                            timestamp=ts,
                        )
                    )

            if self._is_sufficient(parsed_results, idx):
                break

        curated_iocs = self._build_curated_iocs(parsed_results, req, state)
        ioc_support_summary = self._build_ioc_support_summary(curated_iocs)
        for item in curated_iocs:
            ioc_type = item.get("type")
            value = item.get("value")
            if ioc_type in all_iocs and value and value not in all_iocs[ioc_type]:
                all_iocs[ioc_type].append(value)

        status = ToolExecutionStatus.success if query_log else ToolExecutionStatus.failed
        summary = self._summarize(query_log, findings)

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=status,
            summary=summary,
            request=req.model_dump(),
            raw_result={
                "query_log": query_log,
                "parsed_results": parsed_results,
                "focus": req.focus,
                "max_queries": req.max_queries,
                "curated_iocs": curated_iocs,
                "ioc_support_summary": ioc_support_summary,
            },
            findings=findings[:30],
            extracted_iocs=all_iocs,
            duration_ms=int((time.time() - start) * 1000),
            error="" if status == ToolExecutionStatus.success else "No SIEM queries executed successfully",
        )

    @staticmethod
    def _normalize_ioc_text(value: Any, max_len: int = 420) -> str:
        text = str(value or "").strip().strip("\"'`")
        text = re.sub(r"\s+", " ", text)
        if len(text) > max_len:
            return text[: max_len - 3].rstrip() + "..."
        return text

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value or ""))

    @staticmethod
    def _looks_like_url(value: str) -> bool:
        lowered = str(value or "").lower()
        return lowered.startswith("http://") or lowered.startswith("https://")

    @staticmethod
    def _looks_like_domain(value: str) -> bool:
        lowered = str(value or "").lower()
        if SIEMSpecialist._looks_like_url(lowered) or SIEMSpecialist._looks_like_ip(lowered):
            return False
        if lowered.startswith("this."):
            return False
        match = re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,10})",
            lowered,
        )
        if not match:
            return False
        tld = str(match.group(1) or "").lower()
        if tld in SIEMSpecialist.NON_DOMAIN_SUFFIXES:
            return False
        labels = lowered.split(".")
        if any(label in SIEMSpecialist.NON_DOMAIN_TOKENS for label in labels):
            return False
        return True

    @staticmethod
    def _looks_like_hash(value: str) -> bool:
        return bool(re.fullmatch(r"[a-fA-F0-9]{32,128}", str(value or "").strip()))

    @staticmethod
    def _sanitize_command_text(value: str) -> str:
        text = SIEMSpecialist._normalize_ioc_text(value, max_len=520)
        lowered = text.lower()
        if not text:
            return ""
        if lowered.startswith("creating scriptblock text"):
            return ""
        if "scriptblock text (1 of 1)" in lowered:
            return ""
        if lowered in {"/operational", "/denied"}:
            return ""
        return text

    @staticmethod
    def _looks_like_command_text(value: str) -> bool:
        lowered = str(value or "").lower()
        if any(
            noise in lowered
            for noise in (
                "creating scriptblock text",
                "provider lifecycle",
                "engine state is changed",
                "previousenginestate",
                "hostapplication=",
            )
        ):
            return False
        execution_shell = bool(re.search(r"\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd\.exe)\b", lowered))
        high_signal = any(
            marker in lowered
            for marker in (
                "invoke-webrequest",
                "invoke-expression",
                "downloadstring",
                "-encodedcommand",
                "frombase64string",
                "invoke-atomictest",
                "new-smbmapping",
                "net use ",
            )
        )
        if not (execution_shell or high_signal):
            return False
        return len(re.findall(r"[^\s]+", lowered)) >= 3

    @staticmethod
    def _is_script_file_value(value: str) -> bool:
        lowered = str(value or "").lower()
        script_ext = (
            ".ps1",
            ".psm1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js",
            ".py",
            ".sh",
            ".txt",
            ".log",
            ".zip",
            ".rar",
            ".7z",
            ".exe",
            ".dll",
            ".sys",
            ".doc",
            ".docx",
            ".pdf",
        )
        return lowered.endswith(script_ext)

    @staticmethod
    def _looks_like_file_path(value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        if re.match(r"^[A-Za-z]:\\", text):
            pass
        elif text.startswith("\\\\"):
            pass
        else:
            sep_count = text.count("\\") + text.count("/")
            if sep_count < 2:
                return False
        return SIEMSpecialist._is_script_file_value(text)

    @staticmethod
    def _is_high_signal_command(value: str) -> bool:
        lowered = str(value or "").lower()
        if not lowered:
            return False
        if any(
            noise in lowered
            for noise in (
                "creating scriptblock text",
                "provider lifecycle",
                "engine state is changed",
                "previousenginestate",
                "hostapplication=",
                "/operational",
                "/denied",
            )
        ):
            return False
        execution_shell = bool(re.search(r"\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd\.exe)\b", lowered))
        high_signal = any(
            marker in lowered
            for marker in (
                "invoke-webrequest",
                "invoke-expression",
                "downloadstring",
                "-encodedcommand",
                "frombase64string",
                "invoke-atomictest",
                "new-smbmapping",
                "net use ",
                "start-bitstransfer",
                "iwr ",
                "iex ",
            )
        )
        if not (execution_shell and high_signal):
            return False
        token_count = len(re.findall(r"[^\s]+", lowered))
        return token_count >= 4

    @staticmethod
    def _extract_script_files_from_command(command_text: str) -> List[str]:
        if not command_text:
            return []
        out: List[str] = []
        seen: set[str] = set()
        pattern = r"(?:[A-Za-z]:\\|\\\\|/|%[A-Za-z0-9_]+%\\|\.\.?[\\/])[^\s\"']+\.(?:ps1|psm1|bat|cmd|vbs|js|py|sh)\b"
        for match in re.findall(pattern, command_text, flags=re.IGNORECASE):
            normalized = SIEMSpecialist._normalize_ioc_text(match, max_len=260)
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            out.append(normalized)
        return out

    def _build_curated_iocs(
        self,
        parsed_results: List[Dict[str, Any]],
        req: SIEMRequest,
        state: InvestigationState,
    ) -> List[Dict[str, Any]]:
        type_order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "file": 4, "command": 5}
        per_type_limit = 4
        total_limit = 16
        seen: set[str] = set()
        per_type_count: Dict[str, int] = {}
        candidate_rows: List[Dict[str, Any]] = []

        def add(ioc_type: str, value: Any, source: str, evidence: str) -> None:
            normalized = self._normalize_ioc_text(value)
            if not normalized:
                return
            lowered = normalized.lower()
            if lowered in {"/operational", "/denied"}:
                return
            if ioc_type == "command":
                normalized = self._sanitize_command_text(normalized)
                if not normalized:
                    return
                if not self._is_high_signal_command(normalized):
                    return
            if ioc_type == "file":
                if not self._is_script_file_value(normalized):
                    return
                if not self._looks_like_file_path(normalized):
                    return
            if ioc_type == "hash" and not self._looks_like_hash(normalized):
                return
            key = f"{ioc_type}:{normalized.lower()}"
            if key in seen:
                return
            count = per_type_count.get(ioc_type, 0)
            if count >= per_type_limit:
                return
            seen.add(key)
            per_type_count[ioc_type] = count + 1
            candidate_rows.append(
                {
                    "type": ioc_type,
                    "value": normalized,
                    "source": source,
                    "evidence": self._normalize_ioc_text(evidence, max_len=180),
                }
            )

        for result in parsed_results:
            if not isinstance(result, dict):
                continue
            key_events = result.get("key_events")
            if not isinstance(key_events, list):
                continue
            for event in key_events:
                if not isinstance(event, dict):
                    continue
                for ip_field in ("source_ip", "destination_ip"):
                    ip_value = event.get(ip_field)
                    if isinstance(ip_value, str) and self._looks_like_ip(ip_value.strip()):
                        add("ip", ip_value, "siem_specialist", f"Observed in {ip_field.replace('_', ' ')}")

                domain_value = event.get("dns_question")
                if isinstance(domain_value, str) and self._looks_like_domain(domain_value.strip()):
                    add("domain", domain_value, "siem_specialist", "Observed in DNS question")

                url_value = event.get("url_full")
                if isinstance(url_value, str) and self._looks_like_url(url_value.strip()):
                    add("url", url_value, "siem_specialist", "Observed in URL field")

                file_name = event.get("file_name")
                file_path = event.get("file_path")
                if isinstance(file_path, str) and self._is_script_file_value(file_path.strip()):
                    add("file", file_path, "siem_specialist", "Script/file path artifact observed")

                command_text = event.get("process_command_line")
                if isinstance(command_text, str):
                    cleaned_command = self._sanitize_command_text(command_text)
                    if cleaned_command and self._is_high_signal_command(cleaned_command):
                        add("command", cleaned_command, "siem_specialist", "Observed process command line")
                        for script_path in self._extract_script_files_from_command(cleaned_command):
                            add("file", script_path, "siem_specialist", "Script file path from command line")

                for hash_key in ("sha256", "sha1", "md5", "file_hash", "hash"):
                    hash_value = event.get(hash_key)
                    if isinstance(hash_value, str) and self._looks_like_hash(hash_value):
                        add("hash", hash_value, "siem_specialist", f"Observed in {hash_key}")

                message_text = event.get("message")
                if isinstance(message_text, str):
                    for ip_match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message_text):
                        if self._looks_like_ip(ip_match):
                            add("ip", ip_match, "siem_specialist", "Parsed from event message")
                    for url_match in re.findall(r"https?://[^\s\"'<>]+", message_text, flags=re.IGNORECASE):
                        add("url", url_match.rstrip(").,;:"), "siem_specialist", "Parsed from event message")
                    for domain_match in re.findall(
                        r"\b(?=.{1,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
                        message_text,
                        flags=re.IGNORECASE,
                    ):
                        if self._looks_like_domain(domain_match):
                            add("domain", domain_match, "siem_specialist", "Parsed from event message")
                    for hash_match in re.findall(r"\b[a-fA-F0-9]{32,128}\b", message_text):
                        if self._looks_like_hash(hash_match):
                            add("hash", hash_match, "siem_specialist", "Parsed from event message")
                    for file_path in re.findall(
                        r"(?:[A-Za-z]:\\|\\\\|/|%[A-Za-z0-9_]+%\\|\.\.?[\\/])[^\s\"']+\.(?:ps1|psm1|bat|cmd|vbs|js|py|sh|txt|log|zip|rar|7z|exe|dll|sys)\b",
                        message_text,
                        flags=re.IGNORECASE,
                    ):
                        add("file", file_path, "siem_specialist", "Parsed file path from event message")
                    cleaned_message = self._sanitize_command_text(message_text)
                    if cleaned_message and self._is_high_signal_command(cleaned_message):
                        add("command", cleaned_message, "siem_specialist", "Parsed command from event message")
                        for script_path in self._extract_script_files_from_command(cleaned_message):
                            add("file", script_path, "siem_specialist", "Script file path from message command")

        for indicator in req.indicators or []:
            normalized = self._normalize_ioc_text(indicator, max_len=360)
            if not normalized:
                continue
            if self._looks_like_ip(normalized):
                add("ip", normalized, "request", "Indicator from orchestrator request")
            elif self._looks_like_url(normalized):
                add("url", normalized, "request", "Indicator from orchestrator request")
            elif self._looks_like_domain(normalized):
                add("domain", normalized, "request", "Indicator from orchestrator request")
            elif self._looks_like_hash(normalized):
                add("hash", normalized, "request", "Hash indicator from orchestrator request")
            elif self._is_script_file_value(normalized):
                add("file", normalized, "request", "Script/file indicator from orchestrator request")
            elif self._looks_like_command_text(normalized):
                add("command", normalized, "request", "Command-line indicator from orchestrator request")

        candidate_rows = sorted(
            candidate_rows,
            key=lambda row: (type_order.get(str(row.get("type")), 99), str(row.get("value", "")).lower()),
        )
        filtered_rows = self._llm_filter_curated_iocs(candidate_rows, req, state)
        if not filtered_rows:
            filtered_rows = candidate_rows

        selected_keys = {f"{str(row.get('type'))}:{str(row.get('value')).lower()}" for row in filtered_rows}
        for required_type in ("ip", "domain"):
            for row in candidate_rows:
                if str(row.get("type")) != required_type:
                    continue
                row_key = f"{required_type}:{str(row.get('value')).lower()}"
                if row_key in selected_keys:
                    continue
                filtered_rows.append(row)
                selected_keys.add(row_key)
                break

        normalized_rows: List[Dict[str, Any]] = []
        seen_final: set[str] = set()
        final_type_counts: Dict[str, int] = {}
        for row in filtered_rows:
            row_type = str(row.get("type") or "").strip().lower()
            row_value = self._normalize_ioc_text(row.get("value"))
            if row_type not in {"ip", "domain", "url", "hash", "file", "command"}:
                continue
            if not row_value:
                continue
            key = f"{row_type}:{row_value.lower()}"
            if key in seen_final:
                continue
            if final_type_counts.get(row_type, 0) >= per_type_limit:
                continue
            seen_final.add(key)
            final_type_counts[row_type] = final_type_counts.get(row_type, 0) + 1
            normalized_rows.append(
                {
                    "type": row_type,
                    "value": row_value,
                    "source": row.get("source"),
                    "evidence": row.get("evidence"),
                    "context": self._normalize_ioc_text(row.get("context"), max_len=280)
                    if row.get("context")
                    else None,
                }
            )
            if len(normalized_rows) >= total_limit:
                break

        return normalized_rows

    def _llm_filter_curated_iocs(
        self,
        candidates: List[Dict[str, Any]],
        req: SIEMRequest,
        state: InvestigationState,
    ) -> List[Dict[str, Any]]:
        if not candidates:
            return []

        raw_context = getattr(getattr(state, "alert", None), "raw_context", None)
        alert_context = {
            "host_name": req.host_name,
            "alert_timestamp": req.alert_timestamp,
            "focus": req.focus,
            "request_indicators": req.indicators,
            "rule_name": getattr(raw_context, "rule_name", None),
            "rule_description": getattr(raw_context, "rule_description", None),
            "alert_reason": getattr(raw_context, "alert_reason", None),
            "message": getattr(raw_context, "message", None),
            "event_action": getattr(raw_context, "event_action", None),
            "event_code": getattr(raw_context, "event_code", None),
            "event_dataset": getattr(raw_context, "event_dataset", None),
            "process_command_line": getattr(raw_context, "process_command_line", None),
        }
        compact_candidates = [
            {
                "index": idx,
                "type": row.get("type"),
                "value": row.get("value"),
                "source": row.get("source"),
                "evidence": row.get("evidence"),
            }
            for idx, row in enumerate(candidates[:48])
        ]

        prompt = f"""
ACT: SOC IOC Curator.
ROLE: Filter candidate indicators into a compact high-signal IOC list for analyst triage UI.

RULES:
- Output STRICT JSON only.
- Return object: {{"selected":[{{"index":0,"reason":"short justification"}}]}}.
- Select ONLY high-relevance indicators that explain this alert.
- Always include IP and domain indicators when present in candidates.
- For files/scripts, only keep entries that contain a full file path.
- Keep commands only if they materially explain malicious or benign behavior for this alert.
- Prefer fewer, higher-signal entries. Max 12 selections.

ALERT_CONTEXT:
{json.dumps(alert_context, ensure_ascii=False)}

CANDIDATES:
{json.dumps(compact_candidates, ensure_ascii=False)}
"""
        try:
            self.last_prompt = prompt
            self.last_raw_response = ""
            self.last_error = ""
            response = self.llm.generate(prompt)
            self.last_raw_response = response
            payload = extract_json_object(response)
            selected = payload.get("selected")
            if not isinstance(selected, list):
                return candidates[:12]
            out: List[Dict[str, Any]] = []
            seen: set[str] = set()
            for item in selected:
                if not isinstance(item, dict):
                    continue
                idx = item.get("index")
                if not isinstance(idx, int):
                    continue
                if idx < 0 or idx >= len(candidates):
                    continue
                row = candidates[idx]
                key = f"{row.get('type')}:{str(row.get('value')).lower()}"
                if key in seen:
                    continue
                seen.add(key)
                reason = self._normalize_ioc_text(item.get("reason"), max_len=220) if item.get("reason") else ""
                row_payload = dict(row)
                if reason:
                    row_payload["context"] = reason
                out.append(row_payload)
                if len(out) >= 12:
                    break
            return out
        except Exception as exc:
            self.last_error = str(exc)
            return candidates[:12]

    @staticmethod
    def _build_ioc_support_summary(curated_iocs: List[Dict[str, Any]]) -> str:
        if not curated_iocs:
            return (
                "No high-signal IOC artifacts were confirmed in SIEM telemetry for this run. "
                "Analyst action should rely on timeline evidence and host context."
            )

        counts: Dict[str, int] = {}
        for row in curated_iocs:
            ioc_type = str(row.get("type") or "ioc")
            counts[ioc_type] = counts.get(ioc_type, 0) + 1
        ordered_labels = {
            "ip": "IP",
            "domain": "domain",
            "url": "URL",
            "hash": "hash",
            "file": "script/file",
            "command": "command-line",
        }
        fragments = []
        for ioc_type in ("ip", "domain", "url", "hash", "file", "command"):
            count = counts.get(ioc_type, 0)
            if count:
                label = ordered_labels.get(ioc_type, ioc_type)
                fragments.append(f"{count} {label}")
        composition = ", ".join(fragments) if fragments else "no retained indicators"
        return (
            f"Curated IOC set retained {len(curated_iocs)} high-signal artifacts ({composition}) from host telemetry. "
            "Low-signal scriptblock fragments and duplicate noise were dropped."
        )

    def _is_sufficient(self, parsed_results: List[Dict[str, Any]], idx: int) -> bool:
        if idx == 0:
            return False
        total_events = 0
        for item in parsed_results:
            total_events += int(((item.get("results") or {}).get("count") or 0))
        return total_events >= 20 or idx >= 2

    def _summarize(self, query_log: List[Dict[str, Any]], findings: List[EvidenceFinding]) -> str:
        success = sum(1 for q in query_log if q.get("status") == "success")
        failed = sum(1 for q in query_log if q.get("status") != "success")
        return f"SIEM specialist executed {len(query_log)} queries ({success} success, {failed} failed/denied). Findings captured: {len(findings)}."

    def _run_query(
        self,
        choice: SIEMQueryChoice,
        req: SIEMRequest,
        state: InvestigationState,
        policy_engine: PolicyEngine,
        executed_queries: set[str],
    ) -> Dict[str, Any]:
        query_type = choice.query_type
        args = self._sanitize_args(query_type, choice.args, req)
        query_key = json.dumps({"query_type": query_type, "args": args}, sort_keys=True, default=str)
        if query_key in executed_queries:
            return {
                "query_type": query_type,
                "args": args,
                "status": "skipped_duplicate",
                "reason": "Equivalent SIEM query already executed by this specialist action.",
            }
        executed_queries.add(query_key)

        if query_type == "query_recent_host_alerts":
            policy = policy_engine.check_tool_permission(state, "query_recent_host_alerts", args)
            if not policy.allowed:
                return {
                    "query_type": query_type,
                    "args": args,
                    "status": "denied_policy",
                    "reason": policy.reason,
                }
            raw = siem.query_recent_host_alerts(**args)
            normalized_str = normalize_tool_output("query_recent_host_alerts", raw)
            normalized = self._try_json(normalized_str)
            status = "success" if not isinstance(normalized, str) or not normalized.startswith("Error") else "failed"
            return {
                "query_type": query_type,
                "args": args,
                "status": status,
                "normalized": normalized,
            }

        if query_type == "build_siem_query":
            filters = args.get("filters", [])
            raw = query_builder.build_siem_query(filters)
            normalized_str = normalize_tool_output("build_siem_query", raw)
            normalized = self._try_json(normalized_str)
            status = "success" if not isinstance(normalized, str) or not normalized.startswith("Error") else "failed"
            return {
                "query_type": query_type,
                "args": {"filters": filters},
                "status": status,
                "normalized": normalized,
            }

        policy = policy_engine.check_tool_permission(state, "query_siem_host_logs", args)
        if not policy.allowed:
            return {
                "query_type": query_type,
                "args": args,
                "status": "denied_policy",
                "reason": policy.reason,
            }

        raw = siem.query_host_logs(**args)
        normalized_str = normalize_tool_output("query_siem_host_logs", raw)
        normalized = self._try_json(normalized_str)
        status = "success" if not isinstance(normalized, str) or not normalized.startswith("Error") else "failed"

        return {
            "query_type": query_type,
            "args": args,
            "status": status,
            "normalized": normalized,
        }

    def _sanitize_args(self, query_type: str, args: Dict[str, Any], req: SIEMRequest) -> Dict[str, Any]:
        if query_type == "query_recent_host_alerts":
            lookback = int(args.get("lookback_hours", 24))
            lookback = max(1, min(72, lookback))
            return {
                "host_name": req.host_name,
                "lookback_hours": lookback,
            }

        if query_type == "build_siem_query":
            filters = args.get("filters") or []
            if not isinstance(filters, list):
                filters = []
            return {"filters": filters[:8]}

        back = int(args.get("window_back_minutes", 15))
        forward = int(args.get("window_forward_minutes", 15))
        back = max(5, min(120, back))
        forward = max(0, min(120, forward))

        allowed = {
            "host_name": req.host_name,
            "alert_timestamp": req.alert_timestamp,
            "window_back_minutes": back,
            "window_forward_minutes": forward,
        }

        for key in ("process_name", "event_code", "message_contains", "source_ip", "destination_ip", "user_id"):
            value = args.get(key)
            if value:
                allowed[key] = str(value)

        return allowed

    def _choose_next_query(
        self,
        req: SIEMRequest,
        state: InvestigationState,
        query_log: List[Dict[str, Any]],
        idx: int,
    ) -> SIEMQueryChoice:
        # Deterministic starter queries for stability.
        if idx == 0:
            return SIEMQueryChoice(
                query_type="query_recent_host_alerts",
                args={
                    "host_name": req.host_name,
                    "lookback_hours": 24,
                },
                reason="Baseline host alert history",
            )
        if idx == 1:
            baseline_args, baseline_reason = self._build_context_aware_baseline(req, state)
            return SIEMQueryChoice(
                query_type="query_siem_host_logs",
                args=baseline_args,
                reason=baseline_reason,
            )

        # LLM-guided pivot for later loops.
        try:
            return self._llm_choose_query(req, state, query_log)
        except Exception:
            indicator = req.indicators[0] if req.indicators else ""
            fallback_args = {
                "host_name": req.host_name,
                "alert_timestamp": req.alert_timestamp,
                "window_back_minutes": 30,
                "window_forward_minutes": 30,
            }
            if indicator:
                fallback_args["message_contains"] = indicator
            return SIEMQueryChoice(
                query_type="query_siem_host_logs",
                args=fallback_args,
                reason="Fallback SIEM pivot",
            )

    @staticmethod
    def _build_context_aware_baseline(req: SIEMRequest, state: InvestigationState) -> tuple[Dict[str, Any], str]:
        raw_context = getattr(state.alert, "raw_context", None)
        context_parts = [
            str(getattr(raw_context, "message", "") or ""),
            str(getattr(raw_context, "process_command_line", "") or ""),
            str(getattr(raw_context, "event_action", "") or ""),
            str(getattr(raw_context, "event_code", "") or ""),
            " ".join(str(item) for item in (req.indicators or [])),
        ]
        combined = " ".join(context_parts).lower()

        baseline: Dict[str, Any] = {
            "host_name": req.host_name,
            "alert_timestamp": req.alert_timestamp,
            "window_back_minutes": 45,
            "window_forward_minutes": 30,
        }

        powershell_like = any(
            marker in combined
            for marker in (
                "powershell",
                "scriptblock",
                "invoke-webrequest",
                "disablekeepalive",
                "provider lifecycle",
            )
        )
        if powershell_like:
            baseline["event_code"] = "4104"
            preferred_term = None
            for candidate in (
                "Invoke-WebRequest",
                "DisableKeepAlive",
                "Stop-ExecutionLog",
                "Invoke-AtomicTest",
                "Scriptblock",
            ):
                if candidate.lower() in combined:
                    preferred_term = candidate
                    break
            if preferred_term:
                baseline["message_contains"] = preferred_term
            return baseline, "Context-aware PowerShell/script-block pivot around alert timeframe"

        # Fall back to the original provider-lifecycle anchor.
        baseline["event_code"] = "403"
        ioc_hint = next(
            (
                value
                for value in (req.indicators or [])
                if isinstance(value, str) and value.strip() and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.strip())
            ),
            "",
        )
        if ioc_hint:
            baseline["message_contains"] = str(ioc_hint).strip()[:64]
        return baseline, "Baseline host event pivot"

    def _llm_choose_query(
        self,
        req: SIEMRequest,
        state: InvestigationState,
        query_log: List[Dict[str, Any]],
    ) -> SIEMQueryChoice:
        recent_summaries = [ev.summary for ev in state.evidence[-8:]]
        prompt = f"""
ACT: SIEM Specialist Sub-Agent.
ROLE: Choose the next best SIEM query to collect decisive evidence.

RULES:
- Output STRICT JSON only.
- Allowed query_type: query_siem_host_logs, query_recent_host_alerts, build_siem_query, stop.
- Keep windows <= 45 minutes unless strongly justified.
- Reuse host_name and alert_timestamp from request.
- Prefer event_code and message filters anchored in observed evidence.
- For PowerShell-style alerts, prioritize event_code 4104 and message pivots
  (Invoke-WebRequest, ScriptBlock, Stop-ExecutionLog, Invoke-AtomicTest)
  before broadening windows.

REQUEST:
{req.model_dump_json()}

PRIOR_QUERY_LOG:
{json.dumps(query_log, default=str)}

RECENT_EVIDENCE_SUMMARIES:
{json.dumps(recent_summaries, default=str)}

OUTPUT JSON:
{{
  "query_type": "query_siem_host_logs | query_recent_host_alerts | build_siem_query | stop",
  "args": {{"...": "..."}},
  "stop": false,
  "reason": "short reason"
}}
"""
        self.last_prompt = prompt
        self.last_raw_response = ""
        self.last_error = ""

        resp = self.llm.generate(prompt)
        self.last_raw_response = resp
        payload = extract_json_object(resp)

        if payload.get("query_type") == "stop" or payload.get("stop") is True:
            return SIEMQueryChoice(query_type="query_siem_host_logs", args={}, stop=True, reason=payload.get("reason", "stop"))

        return SIEMQueryChoice.model_validate(payload)

    @staticmethod
    def _try_json(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value
