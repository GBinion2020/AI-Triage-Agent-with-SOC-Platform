from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def dict_factory(cursor, row):
    out = {}
    for idx, col in enumerate(cursor.description):
        out[col[0]] = row[idx]
    return out


class TicketStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = dict_factory
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_key TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    alert_id TEXT,
                    severity TEXT,
                    risk_score REAL,
                    status TEXT NOT NULL DEFAULT 'to_do',
                    classification TEXT,
                    verdict TEXT,
                    close_note TEXT,
                    action TEXT,
                    summary TEXT,
                    jira_issue_key TEXT,
                    run_id TEXT,
                    case_folder TEXT,
                    pipeline_log_path TEXT,
                    agent_io_path TEXT,
                    audit_trail_path TEXT,
                    artifacts_path TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(tickets)").fetchall()
            }
            if "jira_issue_key" not in columns:
                conn.execute("ALTER TABLE tickets ADD COLUMN jira_issue_key TEXT")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
                )
                """
            )

    def _next_ticket_key(self, conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) + 1 AS next_id FROM tickets").fetchone()
        next_id = int(row["next_id"])
        return f"SOC-{next_id:05d}"

    def create_ticket(
        self,
        title: str,
        alert_id: Optional[str] = None,
        severity: Optional[str] = None,
        risk_score: Optional[float] = None,
        classification: Optional[str] = None,
        verdict: Optional[str] = None,
        action: Optional[str] = None,
        summary: Optional[str] = None,
        status: str = "to_do",
    ) -> Dict[str, Any]:
        created_at = utc_now_iso()
        with self.connect() as conn:
            ticket_key = self._next_ticket_key(conn)
            conn.execute(
                """
                INSERT INTO tickets (
                    ticket_key, title, alert_id, severity, risk_score, status,
                    classification, verdict, action, summary, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket_key,
                    title,
                    alert_id,
                    severity,
                    risk_score,
                    status,
                    classification,
                    verdict,
                    action,
                    summary,
                    created_at,
                    created_at,
                ),
            )
            ticket_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

        self.add_activity(ticket_id, "ticket_created", {"status": status})
        return self.get_ticket(ticket_id)

    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if not row:
                raise KeyError(f"ticket {ticket_id} not found")
            return row

    def list_tickets(self, status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        clauses = []
        params: List[Any] = []

        if status and status != "all":
            clauses.append("status = ?")
            params.append(status)

        if search:
            token = f"%{search.strip()}%"
            clauses.append("(ticket_key LIKE ? OR title LIKE ? OR alert_id LIKE ?)")
            params.extend([token, token, token])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM tickets {where_sql} ORDER BY id DESC"

        with self.connect() as conn:
            return conn.execute(sql, params).fetchall()

    def update_ticket(self, ticket_id: int, fields: Dict[str, Any]) -> Dict[str, Any]:
        if not fields:
            return self.get_ticket(ticket_id)

        allowed = {
            "title",
            "status",
            "classification",
            "verdict",
            "close_note",
            "action",
            "summary",
            "run_id",
            "jira_issue_key",
            "case_folder",
            "pipeline_log_path",
            "agent_io_path",
            "audit_trail_path",
            "artifacts_path",
            "severity",
            "risk_score",
        }

        updates = []
        params: List[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return self.get_ticket(ticket_id)

        updates.append("updated_at = ?")
        params.append(utc_now_iso())
        params.append(ticket_id)

        with self.connect() as conn:
            conn.execute(f"UPDATE tickets SET {', '.join(updates)} WHERE id = ?", params)

        return self.get_ticket(ticket_id)

    def add_comment(self, ticket_id: int, body: str, author: str = "analyst") -> Dict[str, Any]:
        created_at = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO comments (ticket_id, author, body, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (ticket_id, author, body, created_at),
            )
            comment_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            row = conn.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()

        self.add_activity(ticket_id, "comment_added", {"author": author, "comment_id": comment_id})
        return row

    def list_comments(self, ticket_id: int) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM comments WHERE ticket_id = ? ORDER BY id ASC",
                (ticket_id,),
            ).fetchall()

    def add_activity(self, ticket_id: int, event_type: str, details: Dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO activities (ticket_id, event_type, details_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (ticket_id, event_type, json.dumps(details, default=str), utc_now_iso()),
            )

    def list_activities(self, ticket_id: int) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM activities WHERE ticket_id = ? ORDER BY id ASC",
                (ticket_id,),
            ).fetchall()

        out: List[Dict[str, Any]] = []
        for row in rows:
            parsed = dict(row)
            try:
                parsed["details"] = json.loads(parsed.pop("details_json"))
            except Exception:
                parsed["details"] = {"raw": parsed.pop("details_json")}
            out.append(parsed)
        return out
