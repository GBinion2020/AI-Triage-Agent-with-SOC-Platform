import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from soc_case_ui.app import PipelineRunManager, PipelineSession, app, store
from soc_case_ui.db import TicketStore


def _configure_test_store(tmp_path, monkeypatch):
    db_path = tmp_path / "soc_ui_test.db"
    feedback_db = tmp_path / "feedback.db"
    monkeypatch.setenv("FEEDBACK_DB_PATH", str(feedback_db))
    monkeypatch.delenv("FEEDBACK_DB_URL", raising=False)

    test_store = TicketStore(db_path)
    test_store.init_db()

    import soc_case_ui.app as ui_app

    ui_app.store = test_store
    ui_app.run_manager = PipelineRunManager(test_store)
    return test_store, feedback_db


def test_parse_pipeline_log_prefers_final_output_values(tmp_path):
    log_path = tmp_path / "pipeline_test.log"
    log_path.write_text(
        "\n".join(
            [
                "[+   0.1s] [INFO] [ALERT_INFO]",
                "Alert ID: alert-1",
                "Name: test alert",
                "Severity: high",
                "Risk Score: 89.0",
                "[+  10.0s] [INFO] [FINAL_OUTPUT]",
                "Classification: Suspicious",
                "   Final Score: 29.5",
                "   Action: Close",
                "   Confidence Score: 57.6",
            ]
        ),
        encoding="utf-8",
    )

    parsed = PipelineRunManager._parse_pipeline_log(log_path)
    assert parsed["risk_score"] == 29.5
    assert parsed["action"] == "Close"
    assert parsed["classification"] == "Suspicious"
    assert parsed["confidence_score"] == 57.6


def test_done_requires_fields(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)

    ticket = test_store.create_ticket(
        title="Unit test alert",
        alert_id="alert-1",
        severity="high",
        risk_score=70.0,
        status="to_do",
    )

    with TestClient(app) as client:
        response = client.patch(
            f"/api/tickets/{ticket['id']}",
            json={"status": "done"},
        )

    assert response.status_code == 400
    body = response.json()
    assert "classification" in body["detail"]
    assert test_store.get_ticket(ticket["id"])["status"] == "to_do"


def test_done_syncs_feedback_to_db(tmp_path, monkeypatch):
    test_store, feedback_db = _configure_test_store(tmp_path, monkeypatch)

    ticket = test_store.create_ticket(
        title="Unit test alert",
        alert_id="alert-2",
        severity="high",
        risk_score=70.0,
        status="in_progress",
    )

    with TestClient(app) as client:
        response = client.patch(
            f"/api/tickets/{ticket['id']}",
            json={
                "status": "done",
                "classification": "suspicious",
                "verdict": "close",
                "close_note": "Closed after analyst review.",
            },
        )

    assert response.status_code == 200
    assert response.json()["ticket"]["status"] == "done"

    with sqlite3.connect(feedback_db) as conn:
        row = conn.execute(
            "SELECT issue_key, detection_classification, triage_verdict, close_note FROM jira_feedback ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert row is not None
    assert row[0] == ticket["ticket_key"]
    assert row[1] == "suspicious"
    assert row[2] == "close"
    assert "analyst review" in row[3]


def test_audit_endpoint_returns_graph(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)

    ticket = test_store.create_ticket(
        title="Audit test alert",
        alert_id="alert-3",
        severity="medium",
        risk_score=40.0,
        status="in_progress",
    )

    agent_io_path = tmp_path / "agent_io_test.jsonl"
    agent_io_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-02-24T00:00:00Z",
                "agent_name": "SOCAnalystOrchestrator",
                "input": {"wave": 1},
                "output": {"parsed_plan": {"actions": []}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    artifacts_dir = tmp_path / "tool_results" / "meta"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    run_meta_path = artifacts_dir / "run_metadata_test.json"
    run_meta_path.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "plans": [
                    {
                        "wave": 1,
                        "actions": [
                            {
                                "tool_name": "siem_specialist",
                                "reason": "baseline",
                                "priority": 1,
                                "request": {"host_name": "host-1", "alert_timestamp": "2026-02-24T00:00:00Z"},
                            }
                        ],
                    }
                ],
                "waves": [
                    {
                        "wave": 1,
                        "action_results": [
                            {
                                "action_id": "w1_a1_test",
                                "tool_name": "siem_specialist",
                                "status": "success",
                                "summary": "query succeeded",
                                "request": {},
                                "raw_result": {},
                                "findings": [],
                                "error": "",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    updated = test_store.update_ticket(
        ticket["id"],
        {
            "agent_io_path": str(agent_io_path),
            "artifacts_path": str(Path(tmp_path / "tool_results")),
            "run_id": "run-1",
        },
    )

    assert updated["agent_io_path"] == str(agent_io_path)

    with TestClient(app) as client:
        response = client.get(f"/api/tickets/{ticket['id']}/audit")

    assert response.status_code == 200
    graph = response.json()["graph"]
    assert len(graph["nodes"]) >= 2
    assert isinstance(graph["details"], dict)
    first_node = graph["nodes"][0]
    assert "row" in first_node and "col" in first_node
    assert "input_data" in first_node and "output_data" in first_node


def test_container_style_ticket_paths_resolve_to_local_cases(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)

    import soc_case_ui.app as ui_app

    local_cases_dir = tmp_path / "cases"
    local_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ui_app, "CASES_DIR", local_cases_dir)

    ticket = test_store.create_ticket(
        title="Container path mapping alert",
        alert_id="alert-path-map",
        severity="high",
        risk_score=75.0,
        status="in_progress",
    )

    case_dir = local_cases_dir / "SOC-00001_20260224_120000_abcd1234"
    meta_dir = case_dir / "run_artifacts" / "run-1" / "tool_results" / "meta"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "run_metadata_test.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "waves": [
                    {
                        "wave": 1,
                        "action_results": [
                            {
                                "action_id": "w1_a1_test",
                                "tool_name": "siem_specialist",
                                "status": "success",
                                "summary": "query succeeded",
                                "request": {"host_name": "host-1"},
                                "raw_result": {},
                                "findings": [
                                    {
                                        "title": "Provider Lifecycle",
                                        "detail": "Simulated finding",
                                        "severity": "info",
                                        "timestamp": "2026-02-24T00:00:00Z",
                                    }
                                ],
                                "extracted_iocs": {"ip": [], "domain": ["example.com"], "hash": []},
                                "error": "",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    test_store.update_ticket(
        ticket["id"],
        {
            "run_id": "run-1",
            "case_folder": "/app/cases/SOC-00001_20260224_120000_abcd1234",
            "artifacts_path": "/app/cases/SOC-00001_20260224_120000_abcd1234/run_artifacts/run-1",
        },
    )

    with TestClient(app) as client:
        response = client.get(f"/api/tickets/{ticket['id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["run_health"]["available"] is True
    assert len(body["case_overview"]["events"]) == 1
    assert len(body["case_overview"]["iocs"]) == 1


def test_failed_pipeline_does_not_create_ticket(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)
    manager = PipelineRunManager(test_store)

    class _FakeStdout:
        def __init__(self, lines):
            self._lines = lines
            self._index = 0

        def readline(self):
            if self._index >= len(self._lines):
                return ""
            value = self._lines[self._index]
            self._index += 1
            return value

    class _FakeProcess:
        def __init__(self):
            self.stdout = _FakeStdout(["simulated failure line\n"])
            self.returncode = 1

        def wait(self):
            return None

    monkeypatch.setattr("soc_case_ui.app.subprocess.Popen", lambda *args, **kwargs: _FakeProcess())

    def _unexpected_case_creation(*args, **kwargs):
        raise AssertionError("case creation should not run on failed pipeline")

    monkeypatch.setattr(manager, "_build_case_and_ticket", _unexpected_case_creation)

    session = PipelineSession(
        session_id="test-failed-session",
        started_at=datetime.now(timezone.utc),
        llm_provider="external",
        pipeline_arch="orchestrated",
    )
    manager.current = session
    manager.last = session

    manager._run_pipeline(session)

    assert session.status == "failed"
    assert session.ticket_id is None
    assert session.exit_code == 1
    assert test_store.list_tickets() == []


def test_no_alert_pipeline_does_not_create_ticket(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)
    manager = PipelineRunManager(test_store)

    class _FakeStdout:
        def __init__(self, lines):
            self._lines = lines
            self._index = 0

        def readline(self):
            if self._index >= len(self._lines):
                return ""
            value = self._lines[self._index]
            self._index += 1
            return value

    class _FakeProcess:
        def __init__(self):
            self.stdout = _FakeStdout(
                [
                    "2026-02-24 09:55:45,837 [INFO] Starting Enterprise Agentic SOC...\n",
                    "[pipeline] fetched_alerts=0\n",
                    "[pipeline] result=no_alerts processed_alerts=0\n",
                ]
            )
            self.returncode = 0

        def wait(self):
            return None

    monkeypatch.setattr("soc_case_ui.app.subprocess.Popen", lambda *args, **kwargs: _FakeProcess())

    def _unexpected_case_creation(*args, **kwargs):
        raise AssertionError("case creation should not run when no alerts were processed")

    monkeypatch.setattr(manager, "_build_case_and_ticket", _unexpected_case_creation)

    session = PipelineSession(
        session_id="test-no-alert-session",
        started_at=datetime.now(timezone.utc),
        llm_provider="external",
        pipeline_arch="orchestrated",
    )
    manager.current = session
    manager.last = session

    manager._run_pipeline(session)

    assert session.status == "completed_no_alerts"
    assert session.ticket_id is None
    assert session.exit_code == 0
    assert session.processed_alerts == 0
    assert test_store.list_tickets() == []


def test_pipeline_creates_ticket_when_processed_alerts_positive(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)
    manager = PipelineRunManager(test_store)

    class _FakeStdout:
        def __init__(self, lines):
            self._lines = lines
            self._index = 0

        def readline(self):
            if self._index >= len(self._lines):
                return ""
            value = self._lines[self._index]
            self._index += 1
            return value

    class _FakeProcess:
        def __init__(self):
            self.stdout = _FakeStdout(
                [
                    "2026-02-24 09:55:45,837 [INFO] Starting Enterprise Agentic SOC...\n",
                    "[pipeline] fetched_alerts=1\n",
                    "[pipeline] result=ok processed_alerts=1\n",
                ]
            )
            self.returncode = 0

        def wait(self):
            return None

    monkeypatch.setattr("soc_case_ui.app.subprocess.Popen", lambda *args, **kwargs: _FakeProcess())
    monkeypatch.setattr(manager, "_build_case_and_ticket", lambda *args, **kwargs: 123)

    session = PipelineSession(
        session_id="test-success-session",
        started_at=datetime.now(timezone.utc),
        llm_provider="external",
        pipeline_arch="orchestrated",
    )
    manager.current = session
    manager.last = session

    manager._run_pipeline(session)

    assert session.status == "completed"
    assert session.ticket_id == 123
    assert session.exit_code == 0
    assert session.processed_alerts == 1


def test_zero_exit_with_fetch_error_hint_is_failed(tmp_path, monkeypatch):
    test_store, _ = _configure_test_store(tmp_path, monkeypatch)
    manager = PipelineRunManager(test_store)

    class _FakeStdout:
        def __init__(self, lines):
            self._lines = lines
            self._index = 0

        def readline(self):
            if self._index >= len(self._lines):
                return ""
            value = self._lines[self._index]
            self._index += 1
            return value

    class _FakeProcess:
        def __init__(self):
            self.stdout = _FakeStdout(
                [
                    "Error fetching alerts: HTTPSConnectionPool(host='172.20.10.4', port=9200)\n",
                    "[pipeline] fetched_alerts=0\n",
                ]
            )
            self.returncode = 0

        def wait(self):
            return None

    monkeypatch.setattr("soc_case_ui.app.subprocess.Popen", lambda *args, **kwargs: _FakeProcess())
    monkeypatch.setattr(manager, "_build_case_and_ticket", lambda *args, **kwargs: 999)

    session = PipelineSession(
        session_id="test-fetch-hint-session",
        started_at=datetime.now(timezone.utc),
        llm_provider="external",
        pipeline_arch="orchestrated",
    )
    manager.current = session
    manager.last = session

    manager._run_pipeline(session)

    assert session.status == "failed"
    assert session.ticket_id is None
    assert session.exit_code == 0
