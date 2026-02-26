from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List

from control.policy_engine import PolicyEngine
from orchestrator.models import OrchestratorAction, OrchestratorPlan
from orchestrator.tool_registry import ToolRegistry
from schemas.state import InvestigationState


class OrchestrationPolicy:
    """Deterministic guardrails for wave-based orchestration."""

    def __init__(
        self,
        base_policy: PolicyEngine,
        max_waves: int = None,
        max_actions_per_wave: int = None,
        max_parallel_actions: int = None,
    ):
        self.base_policy = base_policy
        self.max_waves = max_waves if max_waves is not None else int(os.getenv("ORCH_MAX_WAVES", "2"))
        self.max_actions_per_wave = (
            max_actions_per_wave
            if max_actions_per_wave is not None
            else int(os.getenv("ORCH_MAX_ACTIONS_PER_WAVE", "5"))
        )
        self.max_parallel_actions = (
            max_parallel_actions
            if max_parallel_actions is not None
            else int(os.getenv("ORCH_MAX_PARALLEL_ACTIONS", "4"))
        )
        self.max_waves = max(1, min(2, self.max_waves))
        self.max_actions_per_wave = max(1, min(10, self.max_actions_per_wave))
        self.max_parallel_actions = max(1, min(8, self.max_parallel_actions))

    def sanitize_plan(
        self,
        plan: OrchestratorPlan,
        state: InvestigationState,
        registry: ToolRegistry,
    ) -> OrchestratorPlan:
        """Ensure plan is bounded, valid, and policy-compliant."""
        if plan.wave < 1:
            plan.wave = 1
        if plan.wave > self.max_waves:
            plan.wave = self.max_waves

        dedup: Dict[str, OrchestratorAction] = {}
        for action in plan.actions:
            if not registry.exists(action.tool_name):
                continue

            card = registry.get(action.tool_name)
            if not card.enabled_by_default:
                continue

            key = self._hash_action(action)
            if key in dedup:
                continue
            dedup[key] = action

        actions = sorted(dedup.values(), key=lambda x: x.priority)

        # Wave 1 must include SIEM specialist for baseline host evidence.
        if plan.wave == 1 and not any(a.tool_name == "siem_specialist" for a in actions):
            actions.insert(
                0,
                OrchestratorAction(
                    tool_name="siem_specialist",
                    reason="Policy-required baseline host SIEM evidence",
                    request={
                        "host_name": state.alert.entity.host.hostname if state.alert.entity.host else "",
                        "alert_timestamp": state.alert.alert.timestamp.isoformat(),
                        "focus": ["process", "network", "identity"],
                        "max_queries": 3,
                    },
                    priority=1,
                ),
            )

        # If we already have eligible network/hash indicators, ensure VT enrichment is planned.
        if plan.wave >= 2 and not any(a.tool_name == "virustotal_specialist" for a in actions):
            vt_indicators: List[str] = []
            seen_values = set()
            for item in state.ioc_store:
                item_type = str(item.get("type") or "").strip().lower()
                item_value = str(item.get("value") or "").strip()
                if not item_value or item_type not in {"ip", "domain", "url", "hash"}:
                    continue
                lowered = item_value.lower()
                if lowered in seen_values:
                    continue
                seen_values.add(lowered)
                vt_indicators.append(item_value)
                if len(vt_indicators) >= 6:
                    break
            if vt_indicators:
                actions.append(
                    OrchestratorAction(
                        tool_name="virustotal_specialist",
                        reason="Policy-added VT reputation check for curated high-signal indicators",
                        request={"indicators": vt_indicators, "max_indicators": min(6, len(vt_indicators))},
                        priority=3,
                    )
                )

        plan.actions = actions[: self.max_actions_per_wave]
        return plan

    @staticmethod
    def _hash_action(action: OrchestratorAction) -> str:
        blob = json.dumps(
            {
                "tool_name": action.tool_name,
                "request": action.request,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
