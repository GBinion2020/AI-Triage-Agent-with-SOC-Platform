from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field, ValidationError

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


class EntraRequest(BaseModel):
    user_name: Optional[str] = None
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    lookback_hours: int = Field(default=24, ge=1, le=168)
    max_results: int = Field(default=20, ge=1, le=100)


class EntraSpecialist:
    """Entra ID sign-in specialist (build now, activates when creds are configured)."""

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
            req = EntraRequest.model_validate(request)
        except ValidationError as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Invalid Entra request schema: {exc}",
                request=request,
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        creds = self._load_credentials()
        if not creds:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.skipped,
                summary="Entra specialist skipped: tenant credentials not configured.",
                request=req.model_dump(),
                raw_result={"configured": False},
                duration_ms=int((time.time() - start) * 1000),
            )

        try:
            token = self._get_access_token(creds)
            events = self._query_signins(token, req)
        except Exception as exc:
            return ToolExecutionResult(
                action_id=action_id,
                tool_name=card.name,
                status=ToolExecutionStatus.failed,
                summary=f"Entra specialist failed: {exc}",
                request=req.model_dump(),
                error=str(exc),
                duration_ms=int((time.time() - start) * 1000),
            )

        findings: List[EvidenceFinding] = []
        for event in events[:20]:
            findings.append(
                EvidenceFinding(
                    title=f"Entra sign-in ({event.get('status')})",
                    detail=(
                        f"user={event.get('userPrincipalName','')} ip={event.get('ipAddress','')} "
                        f"app={event.get('appDisplayName','')} risk={event.get('riskLevelAggregated','none')}"
                    ),
                    severity="info",
                    timestamp=event.get("createdDateTime", ""),
                )
            )

        summary = f"Entra specialist collected {len(events)} sign-in event(s) in the requested lookback window."

        extracted_iocs = {"ip": [], "domain": [], "hash": []}
        for event in events:
            ip = event.get("ipAddress", "")
            if ip and ip not in extracted_iocs["ip"]:
                extracted_iocs["ip"].append(ip)

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=ToolExecutionStatus.success,
            summary=summary,
            request=req.model_dump(),
            raw_result={"configured": True, "events": events},
            findings=findings,
            extracted_iocs=extracted_iocs,
            duration_ms=int((time.time() - start) * 1000),
        )

    def _load_credentials(self) -> Optional[Dict[str, str]]:
        tenant_id = os.getenv("ENTRA_TENANT_ID", "").strip()
        client_id = os.getenv("ENTRA_CLIENT_ID", "").strip()
        client_secret = os.getenv("ENTRA_CLIENT_SECRET", "").strip()

        if not tenant_id or not client_id or not client_secret:
            return None

        return {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    def _get_access_token(self, creds: Dict[str, str]) -> str:
        token_url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
        data = {
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        resp = requests.post(token_url, data=data, timeout=20)
        resp.raise_for_status()
        payload = resp.json()
        token = payload.get("access_token", "")
        if not token:
            raise RuntimeError("Microsoft Graph token response missing access_token")
        return token

    def _query_signins(self, token: str, req: EntraRequest) -> List[Dict[str, Any]]:
        graph_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        start_time = datetime.now(timezone.utc) - timedelta(hours=req.lookback_hours)

        def _escape_odata(value: str) -> str:
            return value.replace("'", "''")

        filters = [f"createdDateTime ge {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
        if req.user_name:
            filters.append(f"userPrincipalName eq '{_escape_odata(req.user_name)}'")
        if req.user_id:
            filters.append(f"userId eq '{_escape_odata(req.user_id)}'")
        if req.source_ip:
            filters.append(f"ipAddress eq '{_escape_odata(req.source_ip)}'")

        params = {
            "$top": str(req.max_results),
            "$filter": " and ".join(filters),
            "$orderby": "createdDateTime desc",
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        resp = requests.get(graph_url, headers=headers, params=params, timeout=20)
        resp.raise_for_status()
        payload = resp.json()
        events = payload.get("value", [])

        simplified: List[Dict[str, Any]] = []
        for event in events:
            status = (event.get("status") or {}).get("errorCode", 0)
            simplified.append(
                {
                    "createdDateTime": event.get("createdDateTime", ""),
                    "userPrincipalName": event.get("userPrincipalName", ""),
                    "userId": event.get("userId", ""),
                    "ipAddress": event.get("ipAddress", ""),
                    "appDisplayName": event.get("appDisplayName", ""),
                    "riskLevelAggregated": event.get("riskLevelAggregated", "none"),
                    "status": "success" if status == 0 else f"error_{status}",
                }
            )

        return simplified
