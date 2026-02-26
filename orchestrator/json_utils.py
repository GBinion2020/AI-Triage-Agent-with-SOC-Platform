from __future__ import annotations

import json
import re
from typing import Any, Dict


def extract_json_object(text: str) -> Dict[str, Any]:
    """Extract first JSON object from an LLM response."""
    if not text:
        raise ValueError("Empty response")

    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)

    match = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    if not match:
        raise ValueError("No JSON object found")

    candidate = match.group(1)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Mild cleanup for trailing commas.
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        return json.loads(candidate)
