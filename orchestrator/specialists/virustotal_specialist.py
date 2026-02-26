from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Dict, List

from pydantic import BaseModel, Field, ValidationError

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from mcp_server.tools import virustotal
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


class VirusTotalRequest(BaseModel):
    indicators: List[str] = Field(default_factory=list)
    max_indicators: int = Field(default=3, ge=1, le=10)


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
FILE_LIKE_TLDS = {
    "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
    "tmp", "dat", "bin", "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "au3",
    "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx",
}


class VirusTotalSpecialist:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

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
            req = VirusTotalRequest.model_validate(request)
        except ValidationError as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Invalid VirusTotal request: {exc}",
                request=request,
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        indicators = self._collect_indicators(req, state)
        if not indicators:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.skipped,
                summary="VirusTotal specialist skipped: no eligible indicators.",
                request=req.model_dump(),
                duration_ms=int((time.time() - start) * 1000),
            )

        results = []
        findings: List[EvidenceFinding] = []
        extracted_iocs = {"ip": [], "domain": [], "url": [], "hash": []}

        for indicator in indicators:
            ioc_type = self._infer_type(indicator)
            if not ioc_type:
                continue
            output = virustotal.lookup_indicator(indicator=indicator, type=ioc_type)
            results.append({"indicator": indicator, "type": ioc_type, "output": output})
            if indicator not in extracted_iocs[ioc_type]:
                extracted_iocs[ioc_type].append(indicator)
            findings.append(
                EvidenceFinding(
                    title=f"VT {ioc_type} {indicator}",
                    detail=output[:240],
                    severity="info",
                )
            )

        status = ToolExecutionStatus.success if results else ToolExecutionStatus.skipped
        summary = f"VirusTotal specialist processed {len(results)} indicator(s)."

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=status,
            summary=summary,
            request=req.model_dump(),
            raw_result={"results": results},
            findings=findings,
            extracted_iocs=extracted_iocs,
            duration_ms=int((time.time() - start) * 1000),
            error="" if status == ToolExecutionStatus.success else "No indicators were eligible for VT lookup",
        )

    def _collect_indicators(self, req: VirusTotalRequest, state: InvestigationState) -> List[str]:
        indicators: List[str] = []
        for value in req.indicators:
            if self._is_allowed_indicator(value) and value not in indicators:
                indicators.append(value)

        if not indicators:
            for item in state.ioc_store:
                value = str(item.get("value", "")).strip()
                if self._is_allowed_indicator(value) and value not in indicators:
                    indicators.append(value)
                if len(indicators) >= req.max_indicators:
                    break

        return indicators[: req.max_indicators]

    def _is_allowed_indicator(self, value: str) -> bool:
        ioc_type = self._infer_type(value)
        if not ioc_type:
            return False
        if ioc_type != "ip":
            return True
        try:
            ip = ipaddress.ip_address(value)
            return ip.is_global
        except ValueError:
            return False

    def _infer_type(self, value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        lowered = value.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return "url"
        if "\\" in value or "/" in value or " " in value:
            return ""
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
            return "hash"

        if DOMAIN_RE.fullmatch(value):
            tld = lowered.rsplit(".", 1)[-1]
            if tld in FILE_LIKE_TLDS:
                return ""
            return "domain"

        return ""
