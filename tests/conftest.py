from datetime import datetime, timezone

import pytest

from schemas.alert import (
    AlertInfo,
    AnalysisSignals,
    DetectionInfo,
    EntityInfo,
    ExecutionInfo,
    HostInfo,
    NormalizedSecurityAlert,
    RawContext,
)
from schemas.state import InvestigationState


@pytest.fixture
def minimal_state() -> InvestigationState:
    alert = NormalizedSecurityAlert(
        alert=AlertInfo(
            id="test-alert-001",
            name="Test Alert",
            severity="high",
            risk_score=70,
            status="open",
            timestamp=datetime.now(timezone.utc),
            category="unit-test",
            description="Unit test alert",
            type="signal",
        ),
        detection=DetectionInfo(rule_id="rule-1", rule_type="query"),
        execution=ExecutionInfo(),
        entity=EntityInfo(host=HostInfo(hostname="host-1", os="Windows 11")),
        analysis_signals=AnalysisSignals(),
        raw_context=RawContext(
            host_name="host-1",
            event_code="403",
            event_action="Provider Lifecycle",
            process_command_line="powershell.exe",
        ),
        raw_data={},
    )
    return InvestigationState(alert=alert)
