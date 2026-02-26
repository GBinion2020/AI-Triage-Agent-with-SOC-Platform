from control.policy_engine import PolicyEngine
from orchestrator.specialists.virustotal_specialist import VirusTotalSpecialist
from orchestrator.tool_registry import ToolRegistry


class DummyLLM:
    def generate(self, prompt: str) -> str:
        return "{}"


def test_virustotal_specialist_skips_filename_like_indicators(minimal_state, monkeypatch):
    specialist = VirusTotalSpecialist(DummyLLM())
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    card = registry.get("virustotal_specialist")

    calls = []

    def _fake_lookup(indicator: str, type: str):
        calls.append((indicator, type))
        return f"VirusTotal {type.upper()}: {indicator}\nVerdict: BENIGN\nStats: 0 malicious, 0 suspicious, 12 harmless"

    monkeypatch.setattr(
        "orchestrator.specialists.virustotal_specialist.virustotal.lookup_indicator",
        _fake_lookup,
    )

    result = specialist.execute(
        action_id="test-vt-file-skip",
        request={"indicators": ["example.com", "LineNumbers.txt", "C:\\Users\\Public\\sys.zip"]},
        state=minimal_state,
        card=card,
        policy_engine=PolicyEngine(),
    )

    assert result.status.value == "success"
    assert calls == [("example.com", "domain")]
    assert result.extracted_iocs["domain"] == ["example.com"]
    assert "LineNumbers.txt" not in result.extracted_iocs["domain"]
