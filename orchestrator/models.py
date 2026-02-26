from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


class ToolCostClass(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class ToolExecutionStatus(str, Enum):
    success = "success"
    failed = "failed"
    skipped = "skipped"
    denied_policy = "denied_policy"


class ArtifactReference(BaseModel):
    artifact_id: str
    path: str
    content_type: str
    sha256: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    size_bytes: int = 0


class ToolCard(BaseModel):
    name: str
    display_name: str
    description: str
    specialist: str
    enabled_by_default: bool = True
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    guardrails: List[str] = Field(default_factory=list)
    timeout_seconds: int = 30
    max_retries: int = 1
    cost_class: ToolCostClass = ToolCostClass.medium

    @model_validator(mode="after")
    def validate_card(self) -> "ToolCard":
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        return self


class OrchestratorAction(BaseModel):
    tool_name: str
    reason: str
    request: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 50


class OrchestratorPlan(BaseModel):
    objective: str
    wave: int
    actions: List[OrchestratorAction] = Field(default_factory=list)
    confidence_target: float = Field(default=80.0, ge=0.0, le=100.0)


class EvidenceFinding(BaseModel):
    title: str
    detail: str
    severity: str = "info"
    timestamp: Optional[str] = None


class ToolExecutionResult(BaseModel):
    action_id: str
    tool_name: str
    status: ToolExecutionStatus
    summary: str
    request: Dict[str, Any] = Field(default_factory=dict)
    raw_result: Dict[str, Any] = Field(default_factory=dict)
    findings: List[EvidenceFinding] = Field(default_factory=list)
    extracted_iocs: Dict[str, List[str]] = Field(
        default_factory=lambda: {"ip": [], "domain": [], "url": [], "hash": []}
    )
    artifacts: List[ArtifactReference] = Field(default_factory=list)
    duration_ms: int = 0
    error: str = ""


class WaveExecutionReport(BaseModel):
    run_id: str
    alert_id: str
    wave: int
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    actions_planned: List[OrchestratorAction] = Field(default_factory=list)
    action_results: List[ToolExecutionResult] = Field(default_factory=list)


class ConfidenceReport(BaseModel):
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    rationale: str = ""
    should_continue: bool = False


class OrchestratorRunReport(BaseModel):
    run_id: str
    alert_id: str
    plans: List[OrchestratorPlan] = Field(default_factory=list)
    waves: List[WaveExecutionReport] = Field(default_factory=list)
    confidence: ConfidenceReport = Field(default_factory=ConfidenceReport)
    evidence_summary: str = ""
    artifact_refs: List[ArtifactReference] = Field(default_factory=list)
