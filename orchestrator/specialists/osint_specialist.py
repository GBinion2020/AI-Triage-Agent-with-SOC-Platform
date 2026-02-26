from __future__ import annotations

import ipaddress
import os
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, Field, ValidationError

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


TRUSTED_OSINT_DOMAINS = {
    "cisa.gov",
    "attack.mitre.org",
    "microsoft.com",
    "security.microsoft.com",
    "virustotal.com",
    "abuseipdb.com",
    "crowdstrike.com",
    "talosintelligence.com",
    "unit42.paloaltonetworks.com",
}


class OSINTRequest(BaseModel):
    indicators: List[str] = Field(default_factory=list)
    context_hint: str = ""
    max_results_per_indicator: int = Field(default=3, ge=1, le=5)


class OSINTSpecialist:
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
            req = OSINTRequest.model_validate(request)
        except ValidationError as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Invalid OSINT request: {exc}",
                request=request,
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        indicators = self._select_indicators(req, state)
        if not indicators:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.skipped,
                summary="OSINT skipped: no eligible public indicators.",
                request=req.model_dump(),
                raw_result={"queries": [], "results": []},
                duration_ms=int((time.time() - start) * 1000),
            )

        all_results: List[Dict[str, Any]] = []
        findings: List[EvidenceFinding] = []
        query_errors: List[str] = []
        for indicator in indicators:
            try:
                results = self._safe_search(indicator, req.max_results_per_indicator)
            except Exception as exc:
                query_errors.append(f"{indicator}: {exc}")
                continue
            all_results.extend(results)
            for item in results:
                findings.append(
                    EvidenceFinding(
                        title=f"OSINT hit for {indicator}",
                        detail=f"{item.get('title', '')} | {item.get('url', '')}",
                        severity="info",
                        timestamp="",
                    )
                )

        summary = self._summarize(indicators, all_results, query_errors)
        status = ToolExecutionStatus.success if all_results else ToolExecutionStatus.skipped

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=status,
            summary=summary,
            request=req.model_dump(),
            raw_result={
                "results": all_results,
                "context_hint": req.context_hint,
                "query_errors": query_errors,
            },
            findings=findings[:20],
            extracted_iocs={"ip": [], "domain": [], "hash": []},
            duration_ms=int((time.time() - start) * 1000),
            error="" if status == ToolExecutionStatus.success else "No OSINT results returned",
        )

    def _select_indicators(self, req: OSINTRequest, state: InvestigationState) -> List[str]:
        selected: List[str] = []

        for item in req.indicators:
            if self._is_public_searchable(item) and item not in selected:
                selected.append(item)

        if not selected:
            for item in state.ioc_store:
                value = item.get("value", "")
                if self._is_public_searchable(value) and value not in selected:
                    selected.append(value)
                if len(selected) >= 5:
                    break

        return selected[:5]

    def _safe_search(self, indicator: str, max_results: int) -> List[Dict[str, Any]]:
        brave_key = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
        serpapi_key = os.getenv("SERPAPI_API_KEY", "").strip()

        if brave_key:
            return self._search_brave(indicator, brave_key, max_results)
        if serpapi_key:
            return self._search_serpapi(indicator, serpapi_key, max_results)

        # Optional no-key fallback. Keep disabled by default for controlled behavior.
        if os.getenv("OSINT_ENABLE_DUCKDUCKGO", "false").strip().lower() == "true":
            return self._search_duckduckgo(indicator, max_results)

        return []

    def _search_brave(self, query: str, api_key: str, max_results: int) -> List[Dict[str, Any]]:
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
        }
        params = {
            "q": query,
            "count": max_results,
            "safesearch": "strict",
        }
        resp = requests.get(
            "https://api.search.brave.com/res/v1/web/search",
            headers=headers,
            params=params,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in (data.get("web") or {}).get("results", [])[:max_results]:
            url = item.get("url", "")
            if self._is_trusted_url(url):
                results.append(
                    {
                        "title": item.get("title", ""),
                        "url": url,
                        "snippet": item.get("description", ""),
                        "provider": "brave",
                    }
                )
        return results

    def _search_serpapi(self, query: str, api_key: str, max_results: int) -> List[Dict[str, Any]]:
        params = {
            "engine": "google",
            "q": query,
            "num": max_results,
            "safe": "active",
            "api_key": api_key,
        }
        resp = requests.get("https://serpapi.com/search.json", params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("organic_results", [])[:max_results]:
            url = item.get("link", "")
            if self._is_trusted_url(url):
                results.append(
                    {
                        "title": item.get("title", ""),
                        "url": url,
                        "snippet": item.get("snippet", ""),
                        "provider": "serpapi",
                    }
                )
        return results

    def _search_duckduckgo(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        params = {
            "q": query,
            "format": "json",
            "no_html": "1",
            "skip_disambig": "1",
        }
        resp = requests.get("https://api.duckduckgo.com/", params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        results = []

        abstract_url = data.get("AbstractURL", "")
        if abstract_url and self._is_trusted_url(abstract_url):
            results.append(
                {
                    "title": data.get("Heading", "DuckDuckGo result"),
                    "url": abstract_url,
                    "snippet": data.get("AbstractText", ""),
                    "provider": "duckduckgo",
                }
            )

        for topic in data.get("RelatedTopics", [])[:max_results]:
            if isinstance(topic, dict) and topic.get("FirstURL") and self._is_trusted_url(topic.get("FirstURL")):
                results.append(
                    {
                        "title": topic.get("Text", ""),
                        "url": topic.get("FirstURL", ""),
                        "snippet": topic.get("Text", ""),
                        "provider": "duckduckgo",
                    }
                )

        return results[:max_results]

    def _summarize(self, indicators: List[str], results: List[Dict[str, Any]], query_errors: List[str]) -> str:
        if not results:
            if query_errors:
                return (
                    "OSINT specialist could not complete any searches. "
                    f"{len(query_errors)} query error(s) occurred."
                )
            return "OSINT specialist found no safe external intelligence results."
        if query_errors:
            return (
                f"OSINT specialist searched {len(indicators)} indicator(s), returned {len(results)} vetted results, "
                f"and observed {len(query_errors)} query error(s)."
            )
        return f"OSINT specialist searched {len(indicators)} indicator(s) and returned {len(results)} vetted web results."

    def _is_public_searchable(self, value: str) -> bool:
        value = (value or "").strip()
        if not value:
            return False
        try:
            ip = ipaddress.ip_address(value)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            # domain/hash/keyword allowed
            return True

    def _is_trusted_url(self, url: str) -> bool:
        if not url:
            return False

        trusted_only = os.getenv("OSINT_TRUSTED_DOMAINS_ONLY", "true").strip().lower() != "false"
        if not trusted_only:
            return True

        host = urlparse(url).hostname or ""
        host = host.lower()
        if not host:
            return False

        return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_OSINT_DOMAINS)
