import os
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Request, Header, HTTPException, Query
from schemas.feedback import NormalizedJiraFeedback
from feedback_api.db import save_feedback

app = FastAPI(title="SOC Feedback Ingestion")

def _strip_wrapping_quotes(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        return cleaned[1:-1].strip()
    return cleaned

def _read_env_file_value(key: str) -> str | None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("export "):
            raw = raw[len("export ") :].strip()
        if not raw.startswith(f"{key}="):
            continue
        value = raw.split("=", 1)[1]
        value = value.split("#", 1)[0].strip()
        return _strip_wrapping_quotes(value)
    return None

def _env_or_file(key: str, default: str | None = None) -> str | None:
    env_value = os.getenv(key)
    if env_value is not None and env_value.strip():
        return _strip_wrapping_quotes(env_value)
    file_value = _read_env_file_value(key)
    if file_value is not None and file_value.strip():
        return file_value
    return default

def _load_api_key() -> str:
    loaded = _env_or_file("FEEDBACK_API_KEY")
    if loaded:
        return loaded

    return secrets.token_urlsafe(32)


API_KEY = _load_api_key()
if "FEEDBACK_API_KEY" not in os.environ:
    print("FEEDBACK_API_KEY not set in environment. Using key loaded from .env or generated.")

JIRA_CLOSE_NOTE_FIELD = (_env_or_file("JIRA_CLOSE_NOTE_FIELD", "customfield_10101") or "customfield_10101").strip()
JIRA_DETECTION_CLASSIFICATION_FIELD = (_env_or_file("JIRA_DETECTION_CLASSIFICATION_FIELD", "customfield_10100") or "customfield_10100").strip()
JIRA_TRIAGE_VERDICT_FIELD = (_env_or_file("JIRA_TRIAGE_VERDICT_FIELD", "customfield_10099") or "customfield_10099").strip()


def _require_api_key(x_api_key: str | None) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

def _safe_get(mapping: dict, keys: list[str], default: Any = None) -> Any:
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current

def _extract_adf_text(node: Any) -> str:
    """
    Best-effort extraction for Jira rich-text (ADF) structures.
    """
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(_extract_adf_text(item) for item in node)
    if isinstance(node, dict):
        node_type = node.get("type")
        text = node.get("text", "")
        content = node.get("content", [])
        extracted_children = "".join(_extract_adf_text(item) for item in content) if isinstance(content, list) else ""
        if node_type in {"paragraph", "heading", "blockquote", "listItem"} and extracted_children:
            extracted_children = extracted_children + "\n"
        if node_type == "hardBreak":
            return "\n"
        return f"{text}{extracted_children}"
    return str(node)

def _normalize_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (dict, list)):
        extracted = _extract_adf_text(value).strip()
        if extracted:
            return extracted
        return json.dumps(value)
    return str(value)

def _extract_custom_field_text(fields: dict[str, Any], field_name: str) -> str | None:
    raw_value = fields.get(field_name)
    if isinstance(raw_value, dict) and "value" in raw_value:
        return _normalize_text(raw_value.get("value"))
    return _normalize_text(raw_value)

def _normalize_jira_payload(payload: dict) -> dict:
    fields = payload.get("fields", {}) if isinstance(payload, dict) else {}
    received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "source": "jira",
        "received_at": received_at,
        "issue": {
            "id": payload.get("id"),
            "key": payload.get("key"),
            "summary": _safe_get(fields, ["summary"]),
            "updated": _safe_get(fields, ["updated"]),
            "status": _safe_get(fields, ["status", "name"]),
            "project_key": _safe_get(fields, ["project", "key"]),
            "project_name": _safe_get(fields, ["project", "name"]),
        },
        "triage": {
            "description": _normalize_text(_safe_get(fields, ["description"])),
            "close_note": _extract_custom_field_text(fields, JIRA_CLOSE_NOTE_FIELD),
            "detection_classification": _extract_custom_field_text(fields, JIRA_DETECTION_CLASSIFICATION_FIELD),
            "triage_verdict": _extract_custom_field_text(fields, JIRA_TRIAGE_VERDICT_FIELD),
        },
    }

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhook/jira")
async def jira_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
    debug: bool = Query(default=False),
):
    _require_api_key(x_api_key)
    try:
        payload = await request.json()
    except Exception as e:
        print(f"Failed to parse Jira payload JSON: {e}")
        return {"status": "error", "error": "invalid_json"}

    print("=== JIRA WEBHOOK PAYLOAD START ===")
    print(json.dumps(payload, indent=2))
    print("=== JIRA WEBHOOK PAYLOAD END ===")

    try:
        normalized_dict = _normalize_jira_payload(payload)
        normalized = NormalizedJiraFeedback.model_validate(normalized_dict)
    except Exception as e:
        print(f"Failed to normalize Jira payload: {e}")
        return {"status": "error", "error": "normalization_failed"}

    print("=== JIRA WEBHOOK NORMALIZED START ===")
    print(json.dumps(normalized.model_dump(), indent=2))
    print("=== JIRA WEBHOOK NORMALIZED END ===")
    try:
        save_feedback(payload, normalized.model_dump())
    except Exception as e:
        print(f"Feedback DB insert failed: {e}")
    response = {
        "status": "received",
        "received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if debug:
        response["normalized"] = normalized.model_dump()
    return response
