import json

from agents.decision_agent import DecisionAgent
from agents.soc2_decision_agent import SOC2DecisionAgent


class StubLLM:
    def __init__(self, payload: dict):
        self.payload = payload

    def generate(self, prompt: str) -> str:
        return json.dumps(self.payload)


def test_soc2_decision_enforces_deterministic_action_and_distinct_confidence(minimal_state):
    agent = SOC2DecisionAgent(
        StubLLM(
            {
                "summary": "Analyst narrative.",
                "action": "Escalate to Incident Response",
                "confidence_score": 29.5,  # intentionally identical to risk score
                "confidence_rationale": "Model confidence from evidence quality.",
                "mitre_techniques": ["T1041"],
                "journal": ["Step 1"],
            }
        )
    )

    result = agent.decide(
        state=minimal_state,
        orchestration_summary="Wave 1 summary",
        artifact_refs=[],
        scoring={"risk_score": 29.5, "classification": "Suspicious", "evidence_table": []},
    )

    assert result["classification"] == "Suspicious"
    assert result["final_score"] == 29.5
    assert result["action"] == "Close"
    assert result["recommended_action"] == "Escalate to Incident Response"
    assert isinstance(result.get("confidence_score"), (int, float))
    assert result["confidence_score"] != 29.5
    assert 0.0 <= result["confidence_score"] <= 100.0


def test_decision_agent_enforces_deterministic_action(minimal_state):
    agent = DecisionAgent(
        StubLLM(
            {
                "summary": "Analyst narrative.",
                "action": "Escalate to Incident Response",
                "mitre_techniques": [],
                "journal": [],
            }
        )
    )

    result = agent.decide(
        state=minimal_state,
        reasoning_trace="Reasoning trace",
        scoring={"risk_score": 29.5, "classification": "Suspicious", "evidence_table": []},
    )

    assert result["action"] == "Close"
    assert result["recommended_action"] == "Escalate to Incident Response"
    assert isinstance(result.get("confidence_score"), (int, float))
    assert 0.0 <= result["confidence_score"] <= 100.0
