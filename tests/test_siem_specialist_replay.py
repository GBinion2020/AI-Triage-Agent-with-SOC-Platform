import json
from pathlib import Path

from control.policy_engine import PolicyEngine
from orchestrator.specialists.siem_specialist import SIEMSpecialist
from orchestrator.tool_registry import ToolRegistry


class DummyLLM:
    def generate(self, prompt: str) -> str:
        return '{"query_type":"stop","args":{},"stop":true,"reason":"enough evidence"}'


def test_siem_specialist_replay_fixture(monkeypatch, minimal_state):
    fixture_path = Path("tests/fixtures/sample_siem_events.json")
    fixture_payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    def fake_recent_host_alerts(host_name: str, lookback_hours: int = 24):
        return {
            "query_context": {"host_name": host_name, "lookback_hours": lookback_hours, "max_results": 20},
            "results_count": 1,
            "alerts": [
                {
                    "alert_id": "a1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "rule_name": "Test Rule",
                    "severity": "high",
                    "risk_score": 70,
                    "reason": "unit test"
                }
            ]
        }

    def fake_host_logs(**kwargs):
        return fixture_payload

    monkeypatch.setattr("orchestrator.specialists.siem_specialist.siem.query_recent_host_alerts", fake_recent_host_alerts)
    monkeypatch.setattr("orchestrator.specialists.siem_specialist.siem.query_host_logs", fake_host_logs)

    specialist = SIEMSpecialist(DummyLLM())
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    card = registry.get("siem_specialist")

    result = specialist.execute(
        action_id="replay-action",
        request={
            "host_name": "host-1",
            "alert_timestamp": "2026-01-01T00:00:00Z",
            "focus": ["process"],
            "max_queries": 2,
        },
        state=minimal_state,
        card=card,
        policy_engine=PolicyEngine(),
    )

    assert result.status.value == "success"
    assert len(result.findings) >= 1
    assert len(result.raw_result.get("query_log", [])) >= 2
    assert len(minimal_state.tool_history) == 0
