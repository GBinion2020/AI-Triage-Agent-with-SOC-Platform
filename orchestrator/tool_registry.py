from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from orchestrator.models import ToolCard


class ToolRegistry:
    """Loads tool capability cards from disk and validates them."""

    def __init__(self, cards_dir: str = "tool_registry/cards"):
        self.cards_dir = Path(cards_dir)
        self._cards: Dict[str, ToolCard] = {}
        self.reload()

    def reload(self) -> None:
        if not self.cards_dir.exists():
            raise FileNotFoundError(f"Tool cards directory not found: {self.cards_dir}")

        cards: Dict[str, ToolCard] = {}
        for card_path in sorted(self.cards_dir.glob("*.json")):
            raw = json.loads(card_path.read_text(encoding="utf-8"))
            card = ToolCard.model_validate(raw)
            if card.name in cards:
                raise ValueError(f"Duplicate tool card name: {card.name}")
            cards[card.name] = card

        if not cards:
            raise ValueError("No tool capability cards found.")

        self._cards = cards

    def list_cards(self, enabled_only: bool = True) -> List[ToolCard]:
        cards = list(self._cards.values())
        if enabled_only:
            cards = [c for c in cards if c.enabled_by_default]
        return cards

    def get(self, tool_name: str) -> ToolCard:
        if tool_name not in self._cards:
            raise KeyError(f"Unknown tool: {tool_name}")
        return self._cards[tool_name]

    def exists(self, tool_name: str) -> bool:
        return tool_name in self._cards
