from orchestrator.tool_registry import ToolRegistry


def test_tool_registry_loads_cards():
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    cards = registry.list_cards(enabled_only=True)
    names = {card.name for card in cards}

    assert "siem_specialist" in names
    assert "osint_specialist" in names
    assert "entra_specialist" in names
    assert "ioc_enrichment_specialist" in names
    assert "timeline_specialist" in names
    assert "virustotal_specialist" in names


def test_tool_card_schema_metadata_present():
    registry = ToolRegistry(cards_dir="tool_registry/cards")
    card = registry.get("siem_specialist")

    assert card.timeout_seconds > 0
    assert card.max_retries >= 0
    assert isinstance(card.guardrails, list)
    assert "host_name" in card.input_schema["properties"]
