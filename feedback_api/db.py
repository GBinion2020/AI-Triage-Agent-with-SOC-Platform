import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None


def _require_driver() -> None:
    if psycopg is None:
        raise RuntimeError("psycopg is not installed. Install with `python -m pip install psycopg[binary]`.")


def _parse_sqlite_url(db_url: str) -> Optional[str]:
    if db_url.startswith("sqlite:///"):
        return db_url.replace("sqlite:///", "", 1)
    if db_url.startswith("sqlite://"):
        return db_url.replace("sqlite://", "", 1)
    return None


def get_db_config() -> Optional[Tuple[str, str]]:
    db_url = os.getenv("FEEDBACK_DB_URL")
    if db_url:
        sqlite_path = _parse_sqlite_url(db_url)
        if sqlite_path:
            return ("sqlite", sqlite_path)
        return ("postgres", db_url)

    db_path = os.getenv("FEEDBACK_DB_PATH")
    if db_path:
        return ("sqlite", db_path)

    return ("sqlite", str(Path(__file__).resolve().parent / "feedback.db"))


def ensure_schema_postgres(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS jira_feedback (
            id SERIAL PRIMARY KEY,
            received_at TIMESTAMPTZ NOT NULL,
            issue_id BIGINT,
            issue_key TEXT,
            issue_summary TEXT,
            issue_status TEXT,
            project_key TEXT,
            project_name TEXT,
            jira_updated_ms BIGINT,
            detection_classification TEXT,
            triage_verdict TEXT,
            close_note TEXT,
            description TEXT,
            raw_payload JSONB,
            normalized_payload JSONB,
            UNIQUE (issue_key, jira_updated_ms)
        );
        """
    )
    conn.commit()


def ensure_schema_sqlite(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS jira_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            issue_id INTEGER,
            issue_key TEXT,
            issue_summary TEXT,
            issue_status TEXT,
            project_key TEXT,
            project_name TEXT,
            jira_updated_ms INTEGER,
            detection_classification TEXT,
            triage_verdict TEXT,
            close_note TEXT,
            description TEXT,
            raw_payload TEXT,
            normalized_payload TEXT,
            UNIQUE (issue_key, jira_updated_ms)
        );
        """
    )
    conn.commit()


def _extract_row(raw_payload: Dict[str, Any], normalized: Dict[str, Any]) -> Dict[str, Any]:
    issue = normalized.get("issue", {})
    triage = normalized.get("triage", {})

    issue_id = issue.get("id")
    try:
        if issue_id is not None and issue_id != "":
            issue_id = int(issue_id)
    except Exception:
        issue_id = None

    jira_updated_ms = _normalize_jira_updated(issue.get("updated"))

    return {
        "issue_id": issue_id,
        "issue_key": issue.get("key"),
        "issue_summary": issue.get("summary"),
        "issue_status": issue.get("status"),
        "project_key": issue.get("project_key"),
        "project_name": issue.get("project_name"),
        "jira_updated_ms": jira_updated_ms,
        "detection_classification": triage.get("detection_classification"),
        "triage_verdict": triage.get("triage_verdict"),
        "close_note": triage.get("close_note"),
        "description": triage.get("description"),
        "raw_payload": json.dumps(raw_payload),
        "normalized_payload": json.dumps(normalized),
    }


def _normalize_jira_updated(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)

    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)

    # Jira timestamps are often ISO 8601 like 2026-02-23T11:30:00.000+0000
    normalized = text
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    # Convert +0000 to +00:00
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = normalized[:-2] + ":" + normalized[-2:]
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except Exception:
        return None


def insert_feedback_postgres(conn, raw_payload: Dict[str, Any], normalized: Dict[str, Any]) -> None:
    row = _extract_row(raw_payload, normalized)
    conn.execute(
        """
        INSERT INTO jira_feedback (
            received_at,
            issue_id,
            issue_key,
            issue_summary,
            issue_status,
            project_key,
            project_name,
            jira_updated_ms,
            detection_classification,
            triage_verdict,
            close_note,
            description,
            raw_payload,
            normalized_payload
        )
        VALUES (
            now(),
            %(issue_id)s,
            %(issue_key)s,
            %(issue_summary)s,
            %(issue_status)s,
            %(project_key)s,
            %(project_name)s,
            %(jira_updated_ms)s,
            %(detection_classification)s,
            %(triage_verdict)s,
            %(close_note)s,
            %(description)s,
            %(raw_payload)s::jsonb,
            %(normalized_payload)s::jsonb
        )
        ON CONFLICT (issue_key, jira_updated_ms) DO NOTHING;
        """,
        row,
    )
    conn.commit()


def insert_feedback_sqlite(conn: sqlite3.Connection, raw_payload: Dict[str, Any], normalized: Dict[str, Any]) -> None:
    row = _extract_row(raw_payload, normalized)
    conn.execute(
        """
        INSERT OR IGNORE INTO jira_feedback (
            received_at,
            issue_id,
            issue_key,
            issue_summary,
            issue_status,
            project_key,
            project_name,
            jira_updated_ms,
            detection_classification,
            triage_verdict,
            close_note,
            description,
            raw_payload,
            normalized_payload
        )
        VALUES (
            datetime('now'),
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        );
        """,
        (
            row["issue_id"],
            row["issue_key"],
            row["issue_summary"],
            row["issue_status"],
            row["project_key"],
            row["project_name"],
            row["jira_updated_ms"],
            row["detection_classification"],
            row["triage_verdict"],
            row["close_note"],
            row["description"],
            row["raw_payload"],
            row["normalized_payload"],
        ),
    )
    conn.commit()


def save_feedback(raw_payload: Dict[str, Any], normalized: Dict[str, Any]) -> None:
    config = get_db_config()
    if not config:
        return
    db_type, target = config
    if db_type == "postgres":
        _require_driver()
        with psycopg.connect(target) as conn:
            ensure_schema_postgres(conn)
            insert_feedback_postgres(conn, raw_payload, normalized)
        return

    db_path = Path(target)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        ensure_schema_sqlite(conn)
        insert_feedback_sqlite(conn, raw_payload, normalized)
