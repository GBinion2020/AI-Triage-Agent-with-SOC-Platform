from __future__ import annotations

import json
from typing import List

from llm.client import LLMClient
from orchestrator.json_utils import extract_json_object
from orchestrator.models import OrchestratorAction, OrchestratorPlan, ToolExecutionResult
from orchestrator.tool_registry import ToolRegistry
from schemas.state import InvestigationState


class SOCAnalystOrchestrator:
    """Primary orchestrator agent that plans bounded wave actions."""

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.last_prompt: str = ""
        self.last_raw_response: str = ""
        self.last_error: str = ""

    def plan_wave(
        self,
        state: InvestigationState,
        wave: int,
        registry: ToolRegistry,
        prior_results: List[ToolExecutionResult],
    ) -> OrchestratorPlan:
        cards = registry.list_cards(enabled_only=True)
        tool_descriptions = []
        for card in cards:
            tool_descriptions.append(
                {
                    "name": card.name,
                    "description": card.description,
                    "input_schema": card.input_schema,
                    "guardrails": card.guardrails,
                    "timeout_seconds": card.timeout_seconds,
                }
            )

        prior_summary = [
            {
                "tool": r.tool_name,
                "status": r.status.value,
                "summary": r.summary,
                "iocs": r.extracted_iocs,
            }
            for r in prior_results
        ]

        alert_payload = state.alert.model_dump(exclude_none=True, exclude={"raw_data"})
        evidence_summary = [
            {
                "source_tool": e.source_tool,
                "summary": e.summary,
            }
            for e in state.evidence[-20:]
        ]

        prompt = f"""
ACT: Senior SOC Analyst Orchestrator.
ROLE: Plan wave-based evidence collection using available tool specialists.

RULES:
- Max 2 waves total. You are planning wave {wave}.
- Return STRICT JSON only.
- Prefer broad baseline on wave 1; targeted pivots on wave 2.
- Never request destructive actions.
- Do not include internal/private IPs for VT/OSINT requests.
- Keep each request concise and actionable.
- Do not include internal runtime IDs, hashes, or tool execution IDs in objective/reason text.
- Avoid empty/null fields in request payloads; include only parameters needed by the selected tool.
- Keep actions minimal: choose the smallest set that can materially increase confidence.

ALERT:
{json.dumps(alert_payload, default=str)}

CURRENT EVIDENCE (summaries):
{json.dumps(evidence_summary, default=str)}

PRIOR TOOL RESULTS:
{json.dumps(prior_summary, default=str)}

AVAILABLE TOOLS:
{json.dumps(tool_descriptions, default=str)}

OUTPUT JSON SCHEMA:
{{
  "objective": "string",
  "wave": {wave},
  "confidence_target": 80,
  "actions": [
    {{
      "tool_name": "one_of_available_tool_names",
      "reason": "short reason",
      "priority": 1,
      "request": {{"tool_specific": "payload"}}
    }}
  ]
}}
"""

        self.last_prompt = prompt
        self.last_raw_response = ""
        self.last_error = ""

        try:
            response = self.llm.generate(prompt)
            self.last_raw_response = response
            payload = extract_json_object(response)
            plan = OrchestratorPlan.model_validate(payload)
            return plan
        except Exception as exc:
            self.last_error = str(exc)
            return self._fallback_plan(state, wave)

    def _fallback_plan(self, state: InvestigationState, wave: int) -> OrchestratorPlan:
        host_name = state.alert.entity.host.hostname if state.alert.entity.host else ""
        alert_ts = state.alert.alert.timestamp.isoformat()

        actions: List[OrchestratorAction] = []
        if wave == 1:
            actions.append(
                OrchestratorAction(
                    tool_name="siem_specialist",
                    reason="Collect baseline process/network/identity evidence around alert timestamp",
                    priority=1,
                    request={
                        "host_name": host_name,
                        "alert_timestamp": alert_ts,
                        "focus": ["process", "network", "identity"],
                        "max_queries": 3,
                    },
                )
            )
            actions.append(
                OrchestratorAction(
                    tool_name="ioc_enrichment_specialist",
                    reason="Normalize and classify currently known IOCs",
                    priority=2,
                    request={"iocs": state.ioc_store},
                )
            )
        else:
            actions.append(
                OrchestratorAction(
                    tool_name="siem_specialist",
                    reason="Targeted pivot using wave 1 evidence and discovered indicators",
                    priority=1,
                    request={
                        "host_name": host_name,
                        "alert_timestamp": alert_ts,
                        "focus": ["process", "network"],
                        "max_queries": 2,
                        "indicators": [item.get("value") for item in state.ioc_store[:10]],
                    },
                )
            )
            actions.append(
                OrchestratorAction(
                    tool_name="timeline_specialist",
                    reason="Consolidate current findings into chronological timeline",
                    priority=2,
                    request={},
                )
            )

        return OrchestratorPlan(
            objective="Fallback deterministic orchestration plan",
            wave=wave,
            confidence_target=80.0,
            actions=actions,
        )
