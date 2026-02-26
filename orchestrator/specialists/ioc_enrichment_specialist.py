from __future__ import annotations

import ipaddress
import re
import socket
import time
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, Field, ValidationError

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
FILE_LIKE_TLDS = {
    "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
    "tmp", "dat", "bin", "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "au3",
    "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx",
}


class IOCEnrichmentRequest(BaseModel):
    iocs: List[Any] = Field(default_factory=list)


class IOCEnrichmentSpecialist:
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
            req = IOCEnrichmentRequest.model_validate(request)
        except ValidationError as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Invalid IOC enrichment request: {exc}",
                request=request,
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        normalized = self._collect_iocs(req, state)
        findings: List[EvidenceFinding] = []
        enriched: List[Dict[str, Any]] = []

        for ioc_type, values in normalized.items():
            for value in values:
                if ioc_type == "ip":
                    enriched_item = self._enrich_ip(value)
                elif ioc_type == "domain":
                    enriched_item = self._enrich_domain(value)
                else:
                    enriched_item = self._enrich_hash(value)

                enriched_item["ioc_type"] = ioc_type
                enriched_item["value"] = value
                enriched.append(enriched_item)
                findings.append(
                    EvidenceFinding(
                        title=f"IOC {ioc_type} enrichment",
                        detail=str(enriched_item),
                        severity="info",
                    )
                )

        summary = f"IOC enrichment specialist processed {sum(len(v) for v in normalized.values())} IOC(s)."
        status = ToolExecutionStatus.success if enriched else ToolExecutionStatus.skipped

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=status,
            summary=summary,
            request=req.model_dump(),
            raw_result={"enriched_iocs": enriched},
            findings=findings[:30],
            extracted_iocs=normalized,
            duration_ms=int((time.time() - start) * 1000),
            error="" if status == ToolExecutionStatus.success else "No IOC values available for enrichment",
        )

    def _collect_iocs(self, req: IOCEnrichmentRequest, state: InvestigationState) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {"ip": [], "domain": [], "hash": []}

        for item in req.iocs:
            if isinstance(item, dict):
                declared_type = str(item.get("type", "")).lower()
                value = str(item.get("value", "")).strip()
                if not value:
                    continue
                inferred_type = self._infer_type(value)
                if declared_type == "domain" and inferred_type != "domain":
                    ioc_type = ""
                else:
                    ioc_type = inferred_type if inferred_type in out else (declared_type if declared_type in out else "")
                if ioc_type and value not in out[ioc_type]:
                    out[ioc_type].append(value)
            elif isinstance(item, str):
                ioc_type = self._infer_type(item)
                if ioc_type and item not in out[ioc_type]:
                    out[ioc_type].append(item)

        if not any(out.values()):
            for item in state.ioc_store:
                value = str(item.get("value", "")).strip()
                if not value:
                    continue
                inferred_type = self._infer_type(value)
                declared_type = str(item.get("type", "")).lower()
                if declared_type == "domain" and inferred_type != "domain":
                    ioc_type = ""
                else:
                    ioc_type = inferred_type if inferred_type in out else declared_type
                if ioc_type in out and value not in out[ioc_type]:
                    out[ioc_type].append(value)

        return out

    def _infer_type(self, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        if self._looks_like_file_or_command(value):
            return ""
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        if any(regex.match(value) for regex in HASH_RE.values()):
            return "hash"

        if DOMAIN_RE.match(value):
            tld = value.rsplit(".", 1)[-1].lower()
            if tld in FILE_LIKE_TLDS:
                return ""
            return "domain"

        return ""

    @staticmethod
    def _looks_like_file_or_command(value: str) -> bool:
        lower = value.lower()
        if "\\" in value or "/" in value:
            return True
        if ":" in value and value[1:3] == ":\\":
            return True
        if " " in value:
            return True
        if lower.endswith((
            ".exe", ".dll", ".ps1", ".bat", ".cmd", ".au3", ".js", ".vbs", ".txt",
            ".log", ".csv", ".json", ".xml", ".yml", ".yaml", ".tmp", ".dat", ".bin",
            ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
        )):
            return True
        return False

    def _enrich_ip(self, ip_text: str) -> Dict[str, Any]:
        ip_obj = ipaddress.ip_address(ip_text)
        classification = {
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_link_local": ip_obj.is_link_local,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved": ip_obj.is_reserved,
            "is_global": ip_obj.is_global,
        }

        reverse_dns = ""
        try:
            reverse_dns = socket.gethostbyaddr(ip_text)[0]
        except Exception:
            reverse_dns = ""

        return {
            "classification": classification,
            "reverse_dns": reverse_dns,
        }

    def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        tld = domain.split(".")[-1] if "." in domain else ""
        resolved_ips: List[str] = []
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                ip = info[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)
        except Exception:
            resolved_ips = []

        return {
            "tld": tld,
            "resolved_ips": resolved_ips[:10],
        }

    def _enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        algo = "unknown"
        if HASH_RE["md5"].match(hash_value):
            algo = "md5"
        elif HASH_RE["sha1"].match(hash_value):
            algo = "sha1"
        elif HASH_RE["sha256"].match(hash_value):
            algo = "sha256"

        return {
            "algorithm": algo,
            "length": len(hash_value),
        }
