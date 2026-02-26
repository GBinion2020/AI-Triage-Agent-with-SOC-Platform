import sqlite3

from feedback_api.db import _normalize_jira_updated, save_feedback


def test_normalize_jira_updated_numeric():
    assert _normalize_jira_updated(1735689600000) == 1735689600000
    assert _normalize_jira_updated("1735689600000") == 1735689600000


def test_normalize_jira_updated_iso():
    value = _normalize_jira_updated("2026-02-23T11:30:00.000+0000")
    assert isinstance(value, int)
    assert value > 0


def test_normalize_jira_updated_invalid():
    assert _normalize_jira_updated("not-a-date") is None
    assert _normalize_jira_updated(None) is None


def test_feedback_save_normalizes_updated_and_dedupes(monkeypatch, tmp_path):
    db_path = tmp_path / "feedback.db"
    monkeypatch.setenv("FEEDBACK_DB_PATH", str(db_path))
    monkeypatch.delenv("FEEDBACK_DB_URL", raising=False)

    raw_payload = {"id": "1001", "key": "SOC-1"}
    normalized = {
        "issue": {
            "id": "1001",
            "key": "SOC-1",
            "summary": "Test",
            "status": "Done",
            "project_key": "SOC",
            "project_name": "SOC",
            "updated": "2026-02-23T11:30:00.000+0000",
        },
        "triage": {
            "detection_classification": "benign",
            "triage_verdict": "close",
            "close_note": "test",
            "description": "desc",
        },
    }

    save_feedback(raw_payload, normalized)
    save_feedback(raw_payload, normalized)

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("select count(*) from jira_feedback").fetchone()[0]
        updated = conn.execute("select jira_updated_ms from jira_feedback").fetchone()[0]

    assert count == 1
    assert isinstance(updated, int)
