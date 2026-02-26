from control.policy_engine import PolicyEngine
from orchestrator.specialists.ioc_enrichment_specialist import IOCEnrichmentSpecialist
from orchestrator.tool_registry import ToolRegistry


class DummyLLM:
    def generate(self, prompt: str) -> str:
        return "{}"


def test_ioc_enrichment_specialist_basic(minimal_state):
    specialist = IOCEnrichmentSpecialist(DummyLLM())
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    card = registry.get("ioc_enrichment_specialist")

    result = specialist.execute(
        action_id="test-action",
        request={
            "iocs": [
                {"type": "ip", "value": "8.8.8.8"},
                {"type": "domain", "value": "example.com"},
                {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},
            ]
        },
        state=minimal_state,
        card=card,
        policy_engine=PolicyEngine(),
    )

    assert result.status.value == "success"
    assert "processed" in result.summary.lower()
    assert "8.8.8.8" in result.extracted_iocs["ip"]
    assert "example.com" in result.extracted_iocs["domain"]


def test_ioc_enrichment_does_not_treat_file_paths_as_domains(minimal_state):
    specialist = IOCEnrichmentSpecialist(DummyLLM())
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    card = registry.get("ioc_enrichment_specialist")

    result = specialist.execute(
        action_id="test-action-paths",
        request={"iocs": ["C:\\AtomicRedTeam\\atomics\\T1059\\src\\calc.au3", "powershell.exe", "LineNumbers.txt"]},
        state=minimal_state,
        card=card,
        policy_engine=PolicyEngine(),
    )

    assert "C:\\AtomicRedTeam\\atomics\\T1059\\src\\calc.au3" not in result.extracted_iocs["domain"]
    assert "powershell.exe" not in result.extracted_iocs["domain"]
    assert "LineNumbers.txt" not in result.extracted_iocs["domain"]
