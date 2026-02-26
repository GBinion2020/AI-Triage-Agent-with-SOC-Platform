from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Dict, List

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.models import EvidenceFinding, ToolCard, ToolExecutionResult, ToolExecutionStatus
from schemas.state import InvestigationState


class TimelineSpecialist:
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
        timeline: List[Dict[str, Any]] = []

        for ev in state.evidence:
            parsed = self._safe_json(ev.content)
            if not isinstance(parsed, dict):
                continue
            for event in parsed.get("key_events", [])[:25]:
                ts = event.get("timestamp") or event.get("@timestamp")
                if not ts:
                    continue
                timeline.append(
                    {
                        "timestamp": ts,
                        "action": event.get("event_action") or "event",
                        "source_tool": ev.source_tool,
                        "host": event.get("host_name", ""),
                        "detail": event.get("message", ""),
                    }
                )

        timeline.sort(key=lambda item: item.get("timestamp", ""))
        findings: List[EvidenceFinding] = []
        for item in timeline[:40]:
            findings.append(
                EvidenceFinding(
                    title=item.get("action", "event"),
                    detail=item.get("detail", "")[:240],
                    severity="info",
                    timestamp=item.get("timestamp", ""),
                )
            )

        summary = f"Timeline specialist built {len(timeline)} chronological event entries from collected evidence."
        status = ToolExecutionStatus.success if timeline else ToolExecutionStatus.skipped

        return ToolExecutionResult(
            action_id=action_id,
            tool_name=card.name,
            status=status,
            summary=summary,
            request=request,
            raw_result={"timeline": timeline[:200]},
            findings=findings,
            extracted_iocs={"ip": [], "domain": [], "hash": []},
            duration_ms=int((time.time() - start) * 1000),
            error="" if status == ToolExecutionStatus.success else "No timeline events could be extracted",
        )

    @staticmethod
    def _safe_json(value: str) -> Any:
        try:
            return json.loads(value)
        except Exception:
            return None
