from __future__ import annotations

from typing import Any, Dict, Protocol

from control.policy_engine import PolicyEngine
from llm.client import LLMClient
from orchestrator.models import ToolCard, ToolExecutionResult
from schemas.state import InvestigationState


class Specialist(Protocol):
    def execute(
        self,
        action_id: str,
        request: Dict[str, Any],
        state: InvestigationState,
        card: ToolCard,
        policy_engine: PolicyEngine,
    ) -> ToolExecutionResult:
        ...
