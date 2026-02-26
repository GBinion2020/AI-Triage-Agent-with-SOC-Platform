from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, List, Optional
import requests

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from feedback_api.db import save_feedback
from soc_case_ui.db import TicketStore

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = Path(__file__).resolve().parent
FRONTEND_ROOT = UI_ROOT / "frontend"
FRONTEND_DIST = FRONTEND_ROOT / "dist"
PIPELINE_LOG_DIR = REPO_ROOT / "pipeline_logs"
RUNS_DIR = REPO_ROOT / "runs"
CASES_DIR = Path(os.getenv("SOC_UI_CASES_DIR", str(REPO_ROOT / "cases"))).expanduser()
DB_PATH = Path(os.getenv("SOC_UI_DB_PATH", str(UI_ROOT / "soc_ui.db"))).expanduser()
CONTAINER_APP_ROOT = Path("/app")


def _path_variants(raw_path: Path) -> List[Path]:
    """Return possible host/container path variants for persisted ticket paths."""
    variants: List[Path] = [raw_path]

    try:
        rel = raw_path.relative_to(CONTAINER_APP_ROOT)
        variants.append(REPO_ROOT / rel)
        if rel.parts and rel.parts[0] == "cases":
            suffix = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path()
            variants.append(CASES_DIR / suffix)
        if rel.parts and rel.parts[0] == "runs":
            suffix = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path()
            variants.append(RUNS_DIR / suffix)
        if rel.parts and rel.parts[0] == "pipeline_logs":
            suffix = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path()
            variants.append(PIPELINE_LOG_DIR / suffix)
    except ValueError:
        pass

    parts = raw_path.parts
    if "cases" in parts:
        idx = len(parts) - 1 - list(reversed(parts)).index("cases")
        suffix = Path(*parts[idx + 1 :]) if idx + 1 < len(parts) else Path()
        variants.append(CASES_DIR / suffix)
    if "runs" in parts:
        idx = len(parts) - 1 - list(reversed(parts)).index("runs")
        suffix = Path(*parts[idx + 1 :]) if idx + 1 < len(parts) else Path()
        variants.append(RUNS_DIR / suffix)
    if "pipeline_logs" in parts:
        idx = len(parts) - 1 - list(reversed(parts)).index("pipeline_logs")
        suffix = Path(*parts[idx + 1 :]) if idx + 1 < len(parts) else Path()
        variants.append(PIPELINE_LOG_DIR / suffix)

    dedup: List[Path] = []
    seen = set()
    for candidate in variants:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(candidate)
    return dedup


def _resolve_existing_path(raw_path: Optional[str], allow_nonexistent: bool = False) -> Optional[Path]:
    if not raw_path:
        return None
    source = Path(raw_path).expanduser()
    for candidate in _path_variants(source):
        if candidate.exists():
            return candidate.resolve()
    if allow_nonexistent:
        # Prefer host-relative variant if present.
        variants = _path_variants(source)
        return variants[1] if len(variants) > 1 else variants[0]
    return None


class StartPipelineRequest(BaseModel):
    llm_provider: Optional[str] = Field(default=None, description="local | external")
    pipeline_arch: Optional[str] = Field(default="orchestrated", description="orchestrated | legacy")


class TicketUpdateRequest(BaseModel):
    status: Optional[str] = None
    classification: Optional[str] = None
    verdict: Optional[str] = None
    close_note: Optional[str] = None
    title: Optional[str] = None


class CommentCreateRequest(BaseModel):
    author: str = "analyst"
    body: str


@dataclass
class PipelineSession:
    session_id: str
    started_at: datetime
    llm_provider: str
    pipeline_arch: str
    status: str = "running"
    exit_code: Optional[int] = None
    completed_at: Optional[datetime] = None
    ticket_id: Optional[int] = None
    pipeline_result: str = ""
    processed_alerts: int = 0
    error: str = ""
    lines: List[str] = field(default_factory=list)
    lock: Lock = field(default_factory=Lock)


class PipelineRunManager:
    def __init__(self, ticket_store: TicketStore):
        self.ticket_store = ticket_store
        self._lock = Lock()
        self.current: Optional[PipelineSession] = None
        self.last: Optional[PipelineSession] = None

    def start(self, llm_provider: Optional[str], pipeline_arch: Optional[str]) -> PipelineSession:
        provider = (llm_provider or os.getenv("LLM_PROVIDER", "external")).strip().lower()
        if provider not in {"local", "external"}:
            raise ValueError("llm_provider must be local or external")

        arch = (pipeline_arch or os.getenv("PIPELINE_ARCH", "orchestrated")).strip().lower()
        if arch not in {"orchestrated", "legacy"}:
            raise ValueError("pipeline_arch must be orchestrated or legacy")

        with self._lock:
            if self.current and self.current.status == "running":
                raise RuntimeError("Pipeline is already running")

            session = PipelineSession(
                session_id=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f"),
                started_at=datetime.now(timezone.utc),
                llm_provider=provider,
                pipeline_arch=arch,
            )
            self.current = session
            self.last = session

            thread = Thread(target=self._run_pipeline, args=(session,), daemon=True)
            thread.start()
            return session

    def get_session(self) -> Optional[PipelineSession]:
        if self.current:
            return self.current
        return self.last

    def _append_line(self, session: PipelineSession, line: str) -> None:
        cleaned = line.rstrip("\n")
        with session.lock:
            session.lines.append(cleaned)
            # Keep enough for full run trace while bounding memory.
            if len(session.lines) > 12000:
                session.lines = session.lines[-12000:]

    def _run_pipeline(self, session: PipelineSession) -> None:
        started_ts = session.started_at.timestamp()
        output_accumulator: List[str] = []

        cmd = [sys.executable, "main.py"]
        env = os.environ.copy()
        env["LLM_PROVIDER"] = session.llm_provider
        env["PIPELINE_ARCH"] = session.pipeline_arch

        self._append_line(session, f"[ui] Starting pipeline: {' '.join(cmd)}")
        self._append_line(session, f"[ui] Environment: LLM_PROVIDER={session.llm_provider}, PIPELINE_ARCH={session.pipeline_arch}")

        try:
            process = subprocess.Popen(
                cmd,
                cwd=REPO_ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            assert process.stdout is not None
            for line in iter(process.stdout.readline, ""):
                if not line:
                    break
                output_accumulator.append(line)
                self._append_line(session, line)

            process.wait()
            session.exit_code = int(process.returncode)
            outcome = self._parse_pipeline_outcome(output_accumulator)
            session.pipeline_result = str(outcome.get("result") or "")
            session.processed_alerts = int(outcome.get("processed_alerts") or 0)

            if session.exit_code != 0:
                session.status = "failed"
                self._append_line(session, f"[ui] Pipeline failed with exit code {session.exit_code}")
            elif outcome.get("fetch_error_hint"):
                session.status = "failed"
                self._append_line(session, "[ui] Pipeline output indicates alert fetch/connectivity failure")
            elif session.pipeline_result == "no_alerts" or int(outcome.get("fetched_alerts") or 0) == 0:
                session.status = "completed_no_alerts"
                self._append_line(session, "[ui] Pipeline completed: no alerts were ingested, skipping case/ticket creation")
            elif session.processed_alerts <= 0:
                session.status = "completed_no_alerts"
                self._append_line(session, "[ui] Pipeline completed but processed 0 alerts, skipping case/ticket creation")
            else:
                session.status = "completed"
                self._append_line(session, "[ui] Pipeline completed successfully")
                ticket_id = self._build_case_and_ticket(
                    started_ts=started_ts,
                    stdout_text="".join(output_accumulator),
                    session=session,
                )
                if ticket_id:
                    session.ticket_id = ticket_id
                else:
                    session.status = "completed_no_alerts"
                    self._append_line(session, "[ui] No alert artifacts found for this run, skipping case/ticket creation")

            if session.status != "completed":
                self._append_line(session, "[ui] Skipping case/ticket creation because pipeline did not complete successfully")

        except Exception as exc:
            session.status = "failed"
            session.error = str(exc)
            self._append_line(session, f"[ui][error] {exc}")
        finally:
            session.completed_at = datetime.now(timezone.utc)
            with self._lock:
                if self.current and self.current.session_id == session.session_id:
                    self.current = None
                self.last = session

    @staticmethod
    def _parse_pipeline_outcome(lines: List[str]) -> Dict[str, Any]:
        outcome: Dict[str, Any] = {
            "result": "",
            "fetched_alerts": None,
            "processed_alerts": None,
            "fetch_error_hint": False,
        }
        for raw_line in lines:
            line = raw_line.strip()
            lowered = line.lower()
            if "failed to fetch alerts" in lowered or "error fetching alerts" in lowered:
                outcome["fetch_error_hint"] = True
            if not line.startswith("[pipeline] "):
                continue
            token_blob = line.replace("[pipeline] ", "", 1).strip()
            for token in token_blob.split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
                if key in {"fetched_alerts", "processed_alerts"}:
                    try:
                        outcome[key] = int(value)
                    except ValueError:
                        continue
                elif key == "result":
                    outcome["result"] = value
        return outcome

    def _build_case_and_ticket(self, started_ts: float, stdout_text: str, session: PipelineSession) -> Optional[int]:
        pipeline_log = self._latest_file(PIPELINE_LOG_DIR.glob("pipeline_*.log"), started_ts)
        agent_io_log = self._latest_file(PIPELINE_LOG_DIR.glob("agent_io_*.jsonl"), started_ts)
        audit_trail = self._latest_file(REPO_ROOT.glob("audit_trail_*.json"), started_ts)

        if not pipeline_log:
            self._append_line(session, "[ui] No pipeline log found for this run")
            return None

        parsed = self._parse_pipeline_log(pipeline_log) if pipeline_log else {}
        title = parsed.get("alert_name") or "SOC Alert Investigation"
        alert_id = parsed.get("alert_id")
        severity = parsed.get("severity")
        risk_score = parsed.get("risk_score")
        run_id = parsed.get("run_id")
        action = parsed.get("action")
        classification = parsed.get("classification")

        if not alert_id:
            self._append_line(session, "[ui] Missing alert ID in pipeline artifacts")
            return None

        ticket = self.ticket_store.create_ticket(
            title=title,
            alert_id=alert_id,
            severity=severity,
            risk_score=risk_score,
            classification=classification,
            verdict=action,
            action=action,
            summary=None,
            status="to_do",
        )
        try:
            jira_issue_key = _sync_ticket_to_jira(ticket)
            if jira_issue_key and jira_issue_key != ticket.get("jira_issue_key"):
                ticket = self.ticket_store.update_ticket(ticket["id"], {"jira_issue_key": jira_issue_key})
                self.ticket_store.add_activity(
                    ticket["id"],
                    "jira_synced",
                    {"phase": "create", "issue_key": jira_issue_key},
                )
        except Exception as exc:
            self._append_line(session, f"[ui][warn] Jira sync failed during ticket creation: {exc}")
            self.ticket_store.add_activity(
                ticket["id"],
                "jira_sync_failed",
                {"phase": "create", "error": str(exc)},
            )

        short_alert = (alert_id or "manual").replace("/", "_")[:16]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        case_folder = CASES_DIR / f"{ticket['ticket_key']}_{stamp}_{short_alert}"
        case_folder.mkdir(parents=True, exist_ok=True)

        runtime_dir = case_folder / "runtime"
        logs_dir = case_folder / "logs"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)

        stdout_path = runtime_dir / "pipeline_stdout.log"
        stdout_path.write_text(stdout_text, encoding="utf-8", errors="replace")

        copied_pipeline_log = None
        copied_agent_io = None
        copied_audit = None

        if pipeline_log and pipeline_log.exists():
            copied_pipeline_log = logs_dir / pipeline_log.name
            shutil.copy2(pipeline_log, copied_pipeline_log)

        if agent_io_log and agent_io_log.exists():
            copied_agent_io = logs_dir / agent_io_log.name
            shutil.copy2(agent_io_log, copied_agent_io)

        if audit_trail and audit_trail.exists():
            copied_audit = logs_dir / audit_trail.name
            shutil.copy2(audit_trail, copied_audit)

        artifacts_copy_path = None
        run_artifacts = self._resolve_artifacts_dir(parsed)
        if run_artifacts and run_artifacts.exists():
            run_artifacts_dest = case_folder / "run_artifacts" / run_artifacts.name
            run_artifacts_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(run_artifacts, run_artifacts_dest, dirs_exist_ok=True)
            artifacts_copy_path = run_artifacts_dest

        manifest = {
            "ticket_key": ticket["ticket_key"],
            "ticket_id": ticket["id"],
            "jira_issue_key": ticket.get("jira_issue_key"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session.session_id,
            "llm_provider": session.llm_provider,
            "pipeline_arch": session.pipeline_arch,
            "exit_code": session.exit_code,
            "alert": {
                "alert_id": alert_id,
                "name": title,
                "severity": severity,
                "risk_score": risk_score,
            },
            "run": {
                "run_id": run_id,
                "pipeline_log": str(copied_pipeline_log) if copied_pipeline_log else None,
                "agent_io": str(copied_agent_io) if copied_agent_io else None,
                "audit_trail": str(copied_audit) if copied_audit else None,
                "artifacts": str(artifacts_copy_path) if artifacts_copy_path else None,
            },
        }
        (case_folder / "case_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        updated = self.ticket_store.update_ticket(
            ticket["id"],
            {
                "run_id": run_id,
                "case_folder": str(case_folder),
                "pipeline_log_path": str(copied_pipeline_log) if copied_pipeline_log else None,
                "agent_io_path": str(copied_agent_io) if copied_agent_io else None,
                "audit_trail_path": str(copied_audit) if copied_audit else None,
                "artifacts_path": str(artifacts_copy_path) if artifacts_copy_path else None,
                "classification": classification,
                "verdict": action,
                "action": action,
            },
        )
        self.ticket_store.add_activity(
            ticket["id"],
            "pipeline_run_completed",
            {
                "session_id": session.session_id,
                "run_id": run_id,
                "exit_code": session.exit_code,
                "case_folder": str(case_folder),
            },
        )

        self._append_line(session, f"[ui] Case folder created: {case_folder}")
        self._append_line(session, f"[ui] Ticket created: {updated['ticket_key']} (id={updated['id']})")

        return int(updated["id"])

    @staticmethod
    def _latest_file(paths, started_ts: float) -> Optional[Path]:
        candidates: List[Path] = []
        for p in paths:
            try:
                if p.stat().st_mtime >= started_ts - 2:
                    candidates.append(p)
            except FileNotFoundError:
                continue
        if not candidates:
            return None
        candidates.sort(key=lambda x: x.stat().st_mtime)
        return candidates[-1]

    @staticmethod
    def _resolve_artifacts_dir(parsed: Dict[str, Any]) -> Optional[Path]:
        artifact_dir = parsed.get("artifact_directory")
        if artifact_dir:
            path = Path(artifact_dir)
            if path.exists():
                return path

        alert_id = parsed.get("alert_id")
        run_id = parsed.get("run_id")
        if alert_id and run_id:
            candidate = RUNS_DIR / alert_id / run_id
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _parse_pipeline_log(path: Path) -> Dict[str, Any]:
        text = path.read_text(encoding="utf-8", errors="replace")

        def match_last(pattern: str) -> Optional[str]:
            matches = re.findall(pattern, text, flags=re.MULTILINE)
            if not matches:
                return None
            value = matches[-1]
            if isinstance(value, tuple):
                value = value[-1]
            return str(value).strip()

        out: Dict[str, Any] = {
            "alert_id": match_last(r"Alert ID:\s*([^\n]+)"),
            "alert_name": match_last(r"Name:\s*([^\n]+)"),
            "severity": match_last(r"Severity:\s*([^\n]+)"),
            "run_id": match_last(r"Run ID:\s*([^\n]+)"),
            "artifact_directory": match_last(r"Artifact directory:\s*([^\n]+)"),
            "classification": match_last(r"Classification:\s*([^\n]+)"),
            "action": match_last(r"Action:\s*([^\n]+)"),
        }

        risk_raw = (
            match_last(r"Final Score:\s*(-?\d+(?:\.\d+)?)")
            or match_last(r"Risk Score:\s*(-?\d+(?:\.\d+)?)")
        )
        if risk_raw is not None:
            try:
                out["risk_score"] = float(risk_raw)
            except ValueError:
                out["risk_score"] = None
        else:
            out["risk_score"] = None

        confidence_raw = (
            match_last(r"Confidence\s*Score:\s*(-?\d+(?:\.\d+)?)")
            or match_last(r"Confidence:\s*(-?\d+(?:\.\d+)?)")
        )
        if confidence_raw is not None:
            try:
                out["confidence_score"] = float(confidence_raw)
            except ValueError:
                out["confidence_score"] = None
        else:
            out["confidence_score"] = None

        return out


store = TicketStore(DB_PATH)
run_manager = PipelineRunManager(store)

app = FastAPI(title="SOC Case UI", version="1.0.0")
app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets", check_dir=False), name="frontend-assets")
app.mount("/static", StaticFiles(directory=UI_ROOT / "static"), name="static")
templates = Jinja2Templates(directory=str(UI_ROOT / "templates"))


def _frontend_index() -> Optional[Path]:
    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return index_path
    return None


def _spa_or_template(request: Request, template_name: str, context: Optional[Dict[str, Any]] = None):
    index_path = _frontend_index()
    if index_path:
        return FileResponse(
            index_path,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    payload = {"request": request}
    if context:
        payload.update(context)
    return templates.TemplateResponse(template_name, payload)


@app.on_event("startup")
def startup() -> None:
    PIPELINE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    store.init_db()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return _spa_or_template(request, "dashboard.html")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_alias(request: Request):
    return _spa_or_template(request, "dashboard.html")


@app.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request):
    return _spa_or_template(request, "dashboard.html")


@app.get("/cases/{ticket_id}", response_class=HTMLResponse)
def case_detail_page(ticket_id: int, request: Request):
    return _spa_or_template(request, "ticket.html", {"ticket_id": ticket_id})


@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def ticket_page(ticket_id: int, request: Request):
    return _spa_or_template(request, "ticket.html", {"ticket_id": ticket_id})


@app.get("/tickets/{ticket_id}/audit", response_class=HTMLResponse)
def audit_page(ticket_id: int, request: Request):
    return _spa_or_template(request, "audit.html", {"ticket_id": ticket_id})


@app.post("/api/pipeline/start")
def start_pipeline(payload: StartPipelineRequest):
    try:
        session = run_manager.start(payload.llm_provider, payload.pipeline_arch)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "session_id": session.session_id,
        "status": session.status,
        "started_at": session.started_at.isoformat(),
        "llm_provider": session.llm_provider,
        "pipeline_arch": session.pipeline_arch,
    }


@app.get("/api/pipeline/status")
def pipeline_status():
    session = run_manager.get_session()
    if not session:
        return {
            "active": False,
            "status": "idle",
        }

    return {
        "active": session.status == "running",
        "session_id": session.session_id,
        "status": session.status,
        "started_at": session.started_at.isoformat(),
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "exit_code": session.exit_code,
        "ticket_id": session.ticket_id,
        "pipeline_result": session.pipeline_result,
        "processed_alerts": session.processed_alerts,
        "error": session.error,
        "llm_provider": session.llm_provider,
        "pipeline_arch": session.pipeline_arch,
    }


@app.get("/api/pipeline/logs")
def pipeline_logs(cursor: int = Query(default=0, ge=0)):
    session = run_manager.get_session()
    if not session:
        return {
            "session_id": None,
            "lines": [],
            "next_cursor": cursor,
            "completed": True,
            "status": "idle",
            "exit_code": None,
            "ticket_id": None,
        }

    with session.lock:
        total = len(session.lines)
        if cursor > total:
            cursor = total
        new_lines = session.lines[cursor:]

    return {
        "session_id": session.session_id,
        "lines": new_lines,
        "next_cursor": total,
        "completed": session.status != "running",
        "status": session.status,
        "exit_code": session.exit_code,
        "ticket_id": session.ticket_id,
        "pipeline_result": session.pipeline_result,
        "processed_alerts": session.processed_alerts,
        "error": session.error,
    }


@app.get("/api/tickets")
def list_tickets(status: str = "all", q: str = ""):
    tickets = store.list_tickets(status=status, search=q)
    enriched: List[Dict[str, Any]] = []
    for ticket in tickets:
        row = dict(ticket)
        decision_risk_score = _resolve_decision_risk_score(row)
        if decision_risk_score is None:
            decision_risk_score = _extract_score_from_value(row.get("risk_score"))

        if row.get("run_id") or row.get("case_folder") or row.get("artifacts_path"):
            row["pipeline_score"] = _resolve_pipeline_score(_load_run_metadata(row))
        else:
            row["pipeline_score"] = None
        row["decision_risk_score"] = decision_risk_score
        row["display_risk_score"] = decision_risk_score
        row["effective_severity"] = _severity_from_risk_score(decision_risk_score, row.get("severity"))
        enriched.append(row)
    return {"tickets": enriched}


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: int):
    try:
        ticket = store.get_ticket(ticket_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    comments = store.list_comments(ticket_id)
    activities = store.list_activities(ticket_id)
    run_health = _build_run_health(ticket)
    case_overview = _build_case_overview(ticket)

    return {
        "ticket": ticket,
        "comments": comments,
        "activities": activities,
        "run_health": run_health,
        "jira_payload": _build_jira_payload_preview(ticket, case_overview),
        "case_overview": case_overview,
    }


@app.patch("/api/tickets/{ticket_id}")
def update_ticket(ticket_id: int, payload: TicketUpdateRequest):
    try:
        current = store.get_ticket(ticket_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    updates = payload.model_dump(exclude_none=True)
    if not updates:
        return {"ticket": current}

    if "status" in updates:
        updates["status"] = updates["status"].strip().lower()
        if updates["status"] not in {"to_do", "in_progress", "done"}:
            raise HTTPException(status_code=400, detail="status must be to_do, in_progress, or done")

    if updates.get("status") == "done":
        required = {
            "classification": updates.get("classification", current.get("classification")),
            "verdict": updates.get("verdict", current.get("verdict")),
            "close_note": updates.get("close_note", current.get("close_note")),
        }
        missing = [name for name, value in required.items() if not (value or "").strip()]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"To mark Done, fill required fields: {', '.join(missing)}",
            )

    updated = store.update_ticket(ticket_id, updates)

    if "status" in updates:
        store.add_activity(ticket_id, "status_updated", {"from": current["status"], "to": updates["status"]})

    for field in ("classification", "verdict", "close_note", "title"):
        if field in updates:
            store.add_activity(ticket_id, "field_updated", {"field": field})

    if updates.get("status") == "done":
        try:
            jira_issue_key = _sync_ticket_to_jira(updated)
            if jira_issue_key:
                if jira_issue_key != updated.get("jira_issue_key"):
                    updated = store.update_ticket(ticket_id, {"jira_issue_key": jira_issue_key})
                store.add_activity(
                    ticket_id,
                    "jira_synced",
                    {"phase": "closure", "issue_key": jira_issue_key},
                )
            _sync_ticket_to_feedback(updated)
            store.add_activity(ticket_id, "feedback_synced", {"target": "jira_feedback"})
        except Exception as exc:
            # If feedback sync fails, do not leave the ticket in done state.
            store.update_ticket(ticket_id, {"status": current["status"]})
            store.add_activity(
                ticket_id,
                "feedback_sync_failed",
                {"error": str(exc), "rolled_back_to_status": current["status"]},
            )
            raise HTTPException(
                status_code=502,
                detail=f"Ticket status rollback applied because downstream sync failed: {exc}",
            ) from exc

    return {"ticket": updated}


@app.post("/api/tickets/{ticket_id}/comments")
def add_comment(ticket_id: int, payload: CommentCreateRequest):
    try:
        _ = store.get_ticket(ticket_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="comment body is required")

    comment = store.add_comment(ticket_id, body=body, author=(payload.author or "analyst"))
    return {"comment": comment}


@app.get("/api/tickets/{ticket_id}/audit")
def ticket_audit(ticket_id: int):
    try:
        ticket = store.get_ticket(ticket_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    agent_path = _resolve_existing_path(ticket.get("agent_io_path"))
    agent_entries = _read_jsonl(agent_path) if agent_path else []
    run_meta = _load_run_metadata(ticket)

    graph = _build_audit_graph(agent_entries, run_meta)

    return {
        "ticket": {
            "id": ticket["id"],
            "ticket_key": ticket["ticket_key"],
            "title": ticket["title"],
            "status": ticket["status"],
        },
        "graph": graph,
    }


@app.get("/api/tickets/{ticket_id}/case/download")
def download_case(ticket_id: int):
    try:
        ticket = store.get_ticket(ticket_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    case_folder_path = _resolve_existing_path(ticket.get("case_folder"))
    if not case_folder_path:
        raise HTTPException(status_code=404, detail="No case folder available for this ticket")

    case_path = case_folder_path.resolve()
    allowed_root = CASES_DIR.resolve()
    if allowed_root not in case_path.parents and case_path != allowed_root:
        raise HTTPException(status_code=403, detail="Case path is outside allowed directory")

    if not case_path.exists() or not case_path.is_dir():
        raise HTTPException(status_code=404, detail="Case folder not found")

    tmp_dir = Path(tempfile.mkdtemp(prefix="soc_case_zip_"))
    archive_base = tmp_dir / ticket["ticket_key"]
    archive_path = shutil.make_archive(str(archive_base), "zip", root_dir=case_path)

    return FileResponse(
        path=archive_path,
        filename=f"{ticket['ticket_key']}_case.zip",
        media_type="application/zip",
    )


def _sync_ticket_to_feedback(ticket: Dict[str, Any]) -> None:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    description = str(ticket.get("summary") or "").strip() or "SOC UI ticket update"

    raw_payload = {
        "id": str(ticket["id"]),
        "key": ticket["ticket_key"],
        "fields": {
            "summary": ticket["title"],
            "updated": now_ms,
            "status": {"name": _status_label(ticket["status"])},
            "project": {"key": "SOC", "name": "SOC Frontend"},
            "description": description,
            os.getenv("JIRA_CLOSE_NOTE_FIELD", "customfield_10101"): ticket.get("close_note") or "",
            os.getenv("JIRA_DETECTION_CLASSIFICATION_FIELD", "customfield_10100"): ticket.get("classification") or "",
            os.getenv("JIRA_TRIAGE_VERDICT_FIELD", "customfield_10099"): ticket.get("verdict") or "",
        },
    }

    normalized = {
        "source": "soc_ui",
        "received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "issue": {
            "id": ticket["id"],
            "key": ticket["ticket_key"],
            "summary": ticket["title"],
            "updated": now_ms,
            "status": _status_label(ticket["status"]),
            "project_key": "SOC",
            "project_name": "SOC Frontend",
        },
        "triage": {
            "description": description,
            "close_note": ticket.get("close_note") or "",
            "detection_classification": ticket.get("classification") or "",
            "triage_verdict": ticket.get("verdict") or "",
        },
    }

    save_feedback(raw_payload, normalized)


def _jira_sync_enabled() -> bool:
    return os.getenv("JIRA_SYNC_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _jira_sync_required() -> bool:
    return os.getenv("JIRA_SYNC_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _jira_adf(text: str) -> Dict[str, Any]:
    clean_text = (text or "").strip() or "SOC UI ticket update"
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": clean_text}],
            }
        ],
    }


def _jira_status_name(status: str) -> str:
    mapping = {
        "to_do": "To Do",
        "in_progress": "In Progress",
        "done": "Done",
    }
    return mapping.get((status or "").strip().lower(), "To Do")


def _jira_request(
    method: str,
    base_url: str,
    endpoint: str,
    email: str,
    token: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{endpoint}"
    response = requests.request(
        method=method,
        url=url,
        auth=(email, token),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json=payload,
        timeout=25,
    )
    if response.status_code >= 400:
        body = response.text[:600]
        raise RuntimeError(f"Jira API {method} {endpoint} failed ({response.status_code}): {body}")
    if not response.text.strip():
        return {}
    return response.json()


def _jira_transition_issue(base_url: str, email: str, token: str, issue_key: str, status: str) -> None:
    target_names = {
        "to_do": {"to do", "open"},
        "in_progress": {"in progress"},
        "done": {"done", "resolved", "closed"},
    }.get((status or "").strip().lower(), set())
    if not target_names:
        return

    transitions = _jira_request("GET", base_url, f"/rest/api/3/issue/{issue_key}/transitions", email, token)
    items = transitions.get("transitions", []) if isinstance(transitions, dict) else []
    target_id = None
    for item in items:
        name = str(item.get("name", "")).strip().lower()
        if name in target_names:
            target_id = item.get("id")
            break
    if not target_id:
        return

    _jira_request(
        "POST",
        base_url,
        f"/rest/api/3/issue/{issue_key}/transitions",
        email,
        token,
        payload={"transition": {"id": str(target_id)}},
    )


def _sync_ticket_to_jira(ticket: Dict[str, Any]) -> Optional[str]:
    if not _jira_sync_enabled():
        return ticket.get("jira_issue_key")

    jira_base = os.getenv("JIRA_BASE_URL", "").strip()
    jira_email = os.getenv("JIRA_EMAIL", "").strip()
    jira_token = os.getenv("JIRA_API_TOKEN", "").strip()
    jira_project = os.getenv("JIRA_PROJECT_KEY", "SOC").strip() or "SOC"
    jira_issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task").strip() or "Task"

    missing = [
        key
        for key, value in {
            "JIRA_BASE_URL": jira_base,
            "JIRA_EMAIL": jira_email,
            "JIRA_API_TOKEN": jira_token,
        }.items()
        if not value
    ]
    if missing:
        message = f"Jira sync is enabled but required config is missing: {', '.join(missing)}"
        if _jira_sync_required():
            raise RuntimeError(message)
        return ticket.get("jira_issue_key")

    jira_description = str(ticket.get("summary") or "").strip() or "SOC UI ticket update"
    fields = {
        "summary": ticket.get("title") or f"SOC Ticket {ticket.get('ticket_key', '')}",
        "description": _jira_adf(jira_description),
        os.getenv("JIRA_CLOSE_NOTE_FIELD", "customfield_10101"): ticket.get("close_note") or "",
        os.getenv("JIRA_DETECTION_CLASSIFICATION_FIELD", "customfield_10100"): ticket.get("classification") or "",
        os.getenv("JIRA_TRIAGE_VERDICT_FIELD", "customfield_10099"): ticket.get("verdict") or "",
    }

    issue_key = (ticket.get("jira_issue_key") or "").strip()
    if issue_key:
        _jira_request(
            "PUT",
            jira_base,
            f"/rest/api/3/issue/{issue_key}",
            jira_email,
            jira_token,
            payload={"fields": fields},
        )
    else:
        created = _jira_request(
            "POST",
            jira_base,
            "/rest/api/3/issue",
            jira_email,
            jira_token,
            payload={
                "fields": {
                    "project": {"key": jira_project},
                    "issuetype": {"name": jira_issue_type},
                    **fields,
                }
            },
        )
        issue_key = str(created.get("key", "")).strip()
        if not issue_key:
            raise RuntimeError("Jira issue creation succeeded but response did not contain issue key.")

    # Best-effort workflow alignment.
    _jira_transition_issue(jira_base, jira_email, jira_token, issue_key, ticket.get("status", "to_do"))
    if (ticket.get("status") or "").strip().lower() == "done" and (ticket.get("close_note") or "").strip():
        _jira_request(
            "POST",
            jira_base,
            f"/rest/api/3/issue/{issue_key}/comment",
            jira_email,
            jira_token,
            payload={"body": _jira_adf(ticket.get("close_note") or "")},
        )
    return issue_key


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            rows.append(json.loads(text))
        except Exception:
            continue
    return rows


def _ticket_case_roots(ticket: Dict[str, Any]) -> List[Path]:
    roots: List[Path] = []

    def add_root(path: Optional[Path]) -> None:
        if not path:
            return
        candidate = path if path.is_dir() else path.parent
        if not candidate.exists():
            return
        if candidate in roots:
            return
        roots.append(candidate)

    for key in ("artifacts_path", "case_folder", "pipeline_log_path", "agent_io_path", "audit_trail_path"):
        add_root(_resolve_existing_path(ticket.get(key)))

    ticket_key = str(ticket.get("ticket_key") or "").strip()
    if ticket_key and CASES_DIR.exists():
        for folder in sorted(CASES_DIR.glob(f"{ticket_key}_*"), key=lambda item: item.stat().st_mtime, reverse=True):
            add_root(folder)
            if len(roots) >= 6:
                break

    return roots


def _load_run_metadata(ticket: Dict[str, Any]) -> Dict[str, Any]:
    candidates: List[Path] = []
    for root in _ticket_case_roots(ticket):
        candidates.extend(root.rglob("run_metadata_*.json"))

    # Fallback directly to runs/<alert_id>/<run_id>/tool_results/meta when copied paths are unavailable.
    alert_id = str(ticket.get("alert_id") or "").strip()
    run_id = str(ticket.get("run_id") or "").strip()
    if not candidates and alert_id and run_id:
        meta_dir = RUNS_DIR / alert_id / run_id / "tool_results" / "meta"
        if meta_dir.exists():
            candidates.extend(meta_dir.glob("run_metadata_*.json"))

    if not candidates:
        return {}

    candidates = [p for p in candidates if p.exists()]
    if not candidates:
        return {}

    candidates.sort(key=lambda p: p.stat().st_mtime)
    try:
        return json.loads(candidates[-1].read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _build_run_health(ticket: Dict[str, Any]) -> Dict[str, Any]:
    meta = _load_run_metadata(ticket)
    if not meta:
        return {
            "available": False,
            "waves": 0,
            "total_actions": 0,
            "status_counts": {"success": 0, "failed": 0, "skipped": 0, "denied_policy": 0},
            "confidence": None,
            "success_rate": 0.0,
            "has_failures": False,
        }

    counts = {"success": 0, "failed": 0, "skipped": 0, "denied_policy": 0}
    total_actions = 0
    for wave in meta.get("waves", []):
        for result in wave.get("action_results", []):
            status = str(result.get("status", "")).strip()
            if status in counts:
                counts[status] += 1
            total_actions += 1

    return {
        "available": True,
        "run_id": meta.get("run_id"),
        "waves": len(meta.get("waves", [])),
        "total_actions": total_actions,
        "status_counts": counts,
        "confidence": meta.get("confidence"),
        "success_rate": round((counts["success"] / total_actions) * 100, 1) if total_actions else 0.0,
        "has_failures": counts["failed"] > 0,
    }


def _build_triage_journal(ticket: Dict[str, Any]) -> List[Dict[str, Any]]:
    agent_log = _resolve_existing_path(ticket.get("agent_io_path"))
    if not agent_log:
        return []

    rows = _read_jsonl(agent_log)
    journal: List[Dict[str, Any]] = []
    for row in rows:
        agent = str(row.get("agent_name") or "Agent")
        output = row.get("output") if isinstance(row.get("output"), dict) else {}
        parsed_output = output.get("parsed_output") if isinstance(output.get("parsed_output"), dict) else {}

        action = (
            output.get("summary")
            or output.get("parsed_decision")
            or parsed_output.get("summary")
            or parsed_output.get("decision")
            or parsed_output.get("classification")
            or parsed_output.get("action")
            or output.get("decision")
            or output.get("status")
            or "Recorded step"
        )
        finding = (
            output.get("reason")
            or output.get("error")
            or parsed_output
            or output.get("raw_response")
            or output.get("raw_result")
            or output
        )
        journal.append(
            {
                "timestamp": row.get("timestamp"),
                "agent": agent,
                "action": str(action),
                "finding": _compact_for_display(finding),
            }
        )

    return journal[:120]


def _shorten_detail(value: Any, max_len: int = 260) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _looks_like_structured_text(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    return (
        (stripped.startswith("{") and stripped.endswith("}"))
        or (stripped.startswith("[") and stripped.endswith("]"))
    )


def _extract_investigation_summary_section(text: str) -> Optional[str]:
    clean = str(text or "").strip()
    if not clean:
        return None

    match = re.search(
        r"investigation\s+summary\s*:?\*?\s*(.+?)(?:\n-{3,}|\n\s*evidence\s+table\b|$)",
        clean,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None

    extracted = match.group(1).strip()
    if not extracted:
        return None
    return re.sub(r"\s+\n", "\n", extracted)


def _extract_score_from_text(text: Any) -> Optional[float]:
    clean = str(text or "").strip()
    if not clean:
        return None

    patterns = (
        r"final[\s_-]*score[^0-9-]*(-?\d+(?:\.\d+)?)",
        r"risk[\s_-]*score[^0-9-]*(-?\d+(?:\.\d+)?)",
    )
    for pattern in patterns:
        match = re.search(pattern, clean, flags=re.IGNORECASE)
        if not match:
            continue
        try:
            return float(match.group(1))
        except (TypeError, ValueError):
            continue
    return None


def _normalize_percent_score(value: Any) -> Optional[float]:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if 0.0 <= numeric <= 1.0:
        numeric *= 100.0
    return round(max(0.0, min(100.0, numeric)), 1)


def _extract_confidence_from_text(text: Any) -> Optional[float]:
    clean = str(text or "").strip()
    if not clean:
        return None
    match = re.search(
        r"confidence(?:\s+(?:score|level|rate|value|is))?\s*[:=]?\s*(-?\d+(?:\.\d+)?)\s*%?",
        clean,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return _normalize_percent_score(match.group(1))


def _extract_confidence_from_value(value: Any, depth: int = 0) -> Optional[float]:
    if value is None or depth > 6:
        return None
    if isinstance(value, (int, float)):
        return _normalize_percent_score(value)
    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return None
        score = _extract_confidence_from_text(clean)
        if score is not None:
            return score
        if _looks_like_structured_text(clean):
            try:
                parsed = json.loads(clean)
            except Exception:
                return None
            return _extract_confidence_from_value(parsed, depth + 1)
        return None
    if isinstance(value, dict):
        preferred_keys = (
            "confidence",
            "confidence_score",
            "confidence_pct",
            "confidence_percent",
            "confidence_level",
            "classification_confidence",
            "model_confidence",
            "certainty",
            "confidence_boost",
        )
        for key in preferred_keys:
            score = _extract_confidence_from_value(value.get(key), depth + 1)
            if score is not None:
                return score
        return None
    if isinstance(value, list):
        for child in value:
            score = _extract_confidence_from_value(child, depth + 1)
            if score is not None:
                return score
        return None
    return None


def _extract_score_from_value(value: Any, depth: int = 0) -> Optional[float]:
    if value is None or depth > 6:
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return None
        score = _extract_score_from_text(clean)
        if score is not None:
            return score
        if _looks_like_structured_text(clean):
            try:
                parsed = json.loads(clean)
            except Exception:
                return None
            return _extract_score_from_value(parsed, depth + 1)
        return None
    if isinstance(value, dict):
        for key in ("final_score", "risk_score", "score"):
            score = _extract_score_from_value(value.get(key), depth + 1)
            if score is not None:
                return score
        for child in value.values():
            score = _extract_score_from_value(child, depth + 1)
            if score is not None:
                return score
        return None
    if isinstance(value, list):
        for child in value:
            score = _extract_score_from_value(child, depth + 1)
            if score is not None:
                return score
        return None
    return None


def _extract_narrative_from_value(value: Any, depth: int = 0) -> Optional[str]:
    if value is None or depth > 6:
        return None
    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return None

        section = _extract_investigation_summary_section(clean)
        if section:
            return section

        if _looks_like_structured_text(clean):
            try:
                parsed = json.loads(clean)
            except Exception:
                return None
            return _extract_narrative_from_value(parsed, depth + 1)

        return clean

    if isinstance(value, dict):
        preferred_keys = (
            "summary",
            "reason",
            "parsed_decision",
            "decision",
            "description",
            "detail",
            "message",
            "analysis",
            "conclusion",
            "rationale",
            "finding",
            "action",
        )
        for key in preferred_keys:
            candidate = _extract_narrative_from_value(value.get(key), depth + 1)
            if candidate and len(candidate.strip()) >= 24:
                return candidate
        for child in value.values():
            candidate = _extract_narrative_from_value(child, depth + 1)
            if candidate and len(candidate.strip()) >= 24:
                return candidate
        return None

    if isinstance(value, list):
        for child in value:
            candidate = _extract_narrative_from_value(child, depth + 1)
            if candidate:
                return candidate
        return None

    return None


def _resolve_decision_risk_score(ticket: Dict[str, Any], triage_journal: Optional[List[Dict[str, Any]]] = None) -> Optional[float]:
    journal = triage_journal if triage_journal is not None else _build_triage_journal(ticket)
    decision_steps = [
        step for step in (journal or [])
        if any(
            marker in str(step.get("agent") or "").strip().lower()
            for marker in ("soc2decisionagent", "decisionagent")
        )
    ]

    for step in reversed(decision_steps):
        for field_name in ("finding", "summary", "action", "result", "output"):
            score = _extract_score_from_text(step.get(field_name))
            if score is not None:
                return score

    score = _extract_score_from_text(ticket.get("summary"))
    if score is not None:
        return score

    score = _extract_score_from_value(ticket.get("risk_score"))
    if score is not None:
        return score

    pipeline_log = _resolve_existing_path(ticket.get("pipeline_log_path"))
    if pipeline_log:
        parsed = PipelineRunManager._parse_pipeline_log(pipeline_log)
        score = _extract_score_from_value(parsed.get("risk_score"))
        if score is not None:
            return score

    return None


def _resolve_decision_confidence_score(
    ticket: Dict[str, Any],
    triage_journal: Optional[List[Dict[str, Any]]] = None,
) -> Optional[float]:
    journal = triage_journal if triage_journal is not None else _build_triage_journal(ticket)
    decision_steps = [
        step for step in journal
        if any(
            marker in str(step.get("agent") or "").strip().lower()
            for marker in ("soc2decisionagent", "decisionagent")
        )
    ]

    for step in reversed(decision_steps):
        for field_name in ("finding", "summary", "action", "result", "output"):
            score = _extract_confidence_from_value(step.get(field_name))
            if score is not None:
                return score

    # Direct ticket fields are allowed, but free-form summary text is not used
    # for confidence to avoid accidentally mirroring deterministic risk values.
    for field_name in ("confidence_score", "decision_confidence_score", "classification_confidence", "model_confidence"):
        score = _extract_confidence_from_value(ticket.get(field_name))
        if score is not None:
            return score

    pipeline_log = _resolve_existing_path(ticket.get("pipeline_log_path"))
    if pipeline_log:
        parsed = PipelineRunManager._parse_pipeline_log(pipeline_log)
        score = _extract_confidence_from_value(parsed.get("confidence_score"))
        if score is not None:
            return score

    return None


def _extract_action_from_value(value: Any, depth: int = 0) -> Optional[str]:
    if value is None or depth > 6:
        return None
    if isinstance(value, dict):
        for key in ("action", "verdict", "recommended_action", "decision"):
            resolved = _extract_action_from_value(value.get(key), depth + 1)
            if resolved:
                return resolved
        return None
    if isinstance(value, list):
        for item in value:
            resolved = _extract_action_from_value(item, depth + 1)
            if resolved:
                return resolved
        return None

    text = str(value).strip()
    if not text:
        return None

    lower = text.lower()
    if "escalate" in lower:
        return "Escalate to Incident Response"
    if "block" in lower:
        return "Block Asset/User"
    if "close" in lower:
        return "Close"
    if "monitor" in lower:
        return "Monitor"
    return None


def _resolve_decision_action(ticket: Dict[str, Any], triage_journal: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    journal = triage_journal if triage_journal is not None else _build_triage_journal(ticket)
    decision_steps = [
        step for step in (journal or [])
        if any(
            marker in str(step.get("agent") or "").strip().lower()
            for marker in ("soc2decisionagent", "decisionagent")
        )
    ]

    for step in reversed(decision_steps):
        for field_name in ("finding", "action", "result", "output", "summary"):
            action = _extract_action_from_value(step.get(field_name))
            if action:
                return action

    pipeline_log = _resolve_existing_path(ticket.get("pipeline_log_path"))
    if pipeline_log:
        parsed = PipelineRunManager._parse_pipeline_log(pipeline_log)
        action = _extract_action_from_value(parsed.get("action"))
        if action:
            return action

    for field_name in ("action", "verdict"):
        action = _extract_action_from_value(ticket.get(field_name))
        if action:
            return action
    return None


def _safe_iso_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _pipeline_runtime_seconds(meta: Dict[str, Any]) -> Optional[float]:
    starts: List[datetime] = []
    ends: List[datetime] = []
    for wave in meta.get("waves", []) if isinstance(meta, dict) else []:
        started = _safe_iso_datetime(wave.get("started_at"))
        completed = _safe_iso_datetime(wave.get("completed_at"))
        if started:
            starts.append(started)
        if completed:
            ends.append(completed)
    if not starts or not ends:
        return None
    seconds = (max(ends) - min(starts)).total_seconds()
    return round(max(0.0, seconds), 1)


def _resolve_pipeline_score(meta: Dict[str, Any]) -> Optional[float]:
    raw_score: Optional[float] = None
    confidence = meta.get("confidence") if isinstance(meta, dict) else None
    if isinstance(confidence, dict):
        value = confidence.get("score")
        if isinstance(value, (int, float)):
            raw_score = float(value)
    elif isinstance(confidence, (int, float)):
        raw_score = float(confidence)

    if raw_score is None:
        return None

    if 0.0 <= raw_score <= 1.0:
        raw_score *= 100.0
    return round(max(0.0, min(100.0, raw_score)), 1)


def _normalize_vt_verdict(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if "malicious" in text:
        return "malicious"
    if "suspicious" in text:
        return "suspicious"
    if "benign" in text or "harmless" in text or "clean" in text:
        return "benign"
    return text


def _vt_threat_score(verdict: Optional[str], malicious: int, suspicious: int, harmless: int) -> Optional[int]:
    normalized = _normalize_vt_verdict(verdict)
    if normalized == "malicious":
        score = 85 + min(10, malicious * 3) + min(5, suspicious)
        return int(min(100, score))
    if normalized == "suspicious":
        score = 62 + min(20, suspicious * 4) + min(8, malicious * 2)
        return int(min(92, score))
    if normalized == "benign":
        score = max(5, 18 - min(12, harmless // 6))
        return int(score)
    if malicious > 0:
        return int(min(100, 80 + malicious * 3))
    if suspicious > 0:
        return int(min(90, 55 + suspicious * 5))
    return None


def _parse_vt_output(output: Any, indicator: Optional[str] = None, indicator_type: Optional[str] = None) -> Dict[str, Any]:
    text = str(output or "").strip()
    if not text:
        return {}

    header_match = re.search(r"VirusTotal\s+([A-Za-z]+):\s*([^\n]+)", text, flags=re.IGNORECASE)
    if header_match:
        indicator_type = (indicator_type or header_match.group(1)).strip().lower()
        indicator = (indicator or header_match.group(2)).strip()

    verdict_match = re.search(r"Verdict:\s*([^\n]+)", text, flags=re.IGNORECASE)
    verdict = _normalize_vt_verdict(verdict_match.group(1) if verdict_match else None)

    stats_match = re.search(
        r"Stats:\s*(\d+)\s+malicious,\s*(\d+)\s+suspicious,\s*(\d+)\s+harmless",
        text,
        flags=re.IGNORECASE,
    )
    malicious = int(stats_match.group(1)) if stats_match else 0
    suspicious = int(stats_match.group(2)) if stats_match else 0
    harmless = int(stats_match.group(3)) if stats_match else 0

    parsed_indicator = str(indicator or "").strip()
    if not parsed_indicator:
        return {}

    return {
        "indicator": parsed_indicator,
        "type": str(indicator_type or "").strip().lower() or None,
        "verdict": verdict,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
        },
        "score": _vt_threat_score(verdict, malicious, suspicious, harmless),
        "source": "VirusTotal",
    }


_VT_ELIGIBLE_IOC_TYPES = {"domain", "ip", "url", "hash", "file"}
_UI_ALLOWED_IOC_TYPES = {"domain", "ip", "url", "hash", "file", "command"}
_NON_DOMAIN_SUFFIXES = {
    "ps",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "py",
    "sh",
    "txt",
    "log",
    "csv",
    "json",
    "xml",
    "yml",
    "yaml",
    "ini",
    "cfg",
    "conf",
    "zip",
    "rar",
    "7z",
    "exe",
    "dll",
    "sys",
    "doc",
    "docx",
    "pdf",
    "exception",
    "innerexception",
    "psmessagedetails",
    "scriptblock",
    "runspaceid",
    "psobject",
    "properties",
}
_NON_DOMAIN_TOKENS = {
    "this",
    "exception",
    "innerexception",
    "psmessagedetails",
    "scriptblock",
    "runspaceid",
    "psobject",
    "properties",
}


def _is_vt_eligible_ioc_type(ioc_type: Optional[str]) -> bool:
    return str(ioc_type or "").strip().lower() in _VT_ELIGIBLE_IOC_TYPES


def _normalize_ioc_value(value: Any, max_len: int = 1400) -> str:
    text = str(value or "").strip().strip("\"'`")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[:max_len]
    return text


def _sanitize_command_ioc(text: str) -> str:
    normalized = _normalize_ioc_value(text, max_len=520)
    lowered = normalized.lower()
    if not normalized:
        return ""
    if lowered.startswith("creating scriptblock text"):
        return ""
    if "scriptblock text (1 of 1)" in lowered:
        return ""
    return normalized


def _looks_like_file_path_ioc(text: str) -> bool:
    value = str(text or "").strip()
    if not value:
        return False
    if re.match(r"^[A-Za-z]:\\", value):
        pass
    elif value.startswith("\\\\"):
        pass
    else:
        sep_count = value.count("\\") + value.count("/")
        if sep_count < 2:
            return False
    lowered = value.lower()
    return bool(
        re.search(
            r"\.(ps1|psm1|bat|cmd|vbs|js|py|sh|txt|log|csv|json|xml|yml|yaml|ini|cfg|conf|zip|rar|7z|exe|dll|sys|doc|docx|pdf|xls|xlsx|ppt|pptx|tmp|dat|bin)$",
            lowered,
        )
    )


def _is_noise_ioc_value(value: str, ioc_type: str) -> bool:
    text = _normalize_ioc_value(value, max_len=900)
    lowered = text.lower()
    if not text:
        return True
    if lowered in {"/operational", "/denied"}:
        return True
    if lowered in {"operational", "denied"}:
        return True
    if lowered.startswith("creating scriptblock text"):
        return True
    if "scriptblock text (1 of 1)" in lowered:
        return True
    if ioc_type == "file":
        # Reject generic slash-only pseudo paths with no actionable artifact value.
        if lowered.startswith("/") and "\\" not in lowered and "." not in lowered:
            return True
        if not _looks_like_file_path_ioc(text):
            return True
    if ioc_type == "command":
        token_count = len(re.findall(r"[^\s]+", text))
        if token_count < 3:
            return True
    return False


def _normalize_curated_ioc_value(value: Any, ioc_type: str) -> str:
    text = _normalize_ioc_value(value)
    if ioc_type == "command":
        text = _sanitize_command_ioc(text)
    return text


def _looks_like_command_text(text: str) -> bool:
    cleaned = str(text or "").strip()
    if not cleaned:
        return False
    lowered = cleaned.lower()
    if any(
        noise in lowered
        for noise in (
            "creating scriptblock text",
            "provider lifecycle",
            "engine state is changed",
            "previousenginestate",
            "hostapplication=",
        )
    ):
        return False
    execution_shell = bool(re.search(r"\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd\.exe)\b", lowered))
    high_signal = any(
        marker in lowered
        for marker in (
            "invoke-webrequest",
            "invoke-expression",
            "downloadstring",
            "-encodedcommand",
            "frombase64string",
            "invoke-atomictest",
            "new-smbmapping",
            "net use ",
            "start-bitstransfer",
            "iwr ",
            "iex ",
        )
    )
    if not (execution_shell or high_signal):
        return False
    token_count = len(re.findall(r"[^\s]+", cleaned))
    return token_count >= 3


def _extract_iocs_from_text(value: Any) -> List[Dict[str, str]]:
    text = str(value or "").strip()
    if not text:
        return []

    out: List[Dict[str, str]] = []
    seen: set[str] = set()

    def add(ioc_type: str, raw: str) -> None:
        normalized = _normalize_ioc_value(raw)
        if not normalized:
            return
        key = f"{ioc_type}:{normalized.lower()}"
        if key in seen:
            return
        seen.add(key)
        out.append({"type": ioc_type, "value": normalized})

    for match in re.findall(r"https?://[^\s\"'<>]+", text, flags=re.IGNORECASE):
        add("url", match.rstrip(").,;:"))

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        add("ip", match)

    for match in re.findall(r"\b[a-fA-F0-9]{32,128}\b", text):
        add("hash", match)

    for match in re.findall(r"\b(?:[a-zA-Z]:\\[^\s\"']+|/[^\s\"']+)\b", text):
        add("file", match.rstrip(").,;:"))

    for match in re.findall(r"\b[^\s\"']+\.(?:txt|log|csv|json|xml|yml|yaml|ini|cfg|conf|zip|rar|7z|exe|dll|sys|bat|ps1|vbs|js|doc|docx|pdf|xls|xlsx|ppt|pptx|tmp|dat|bin)\b", text, flags=re.IGNORECASE):
        add("file", match.rstrip(").,;:"))

    domain_pattern = re.compile(
        r"\b(?=.{1,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,10})\b",
        flags=re.IGNORECASE,
    )
    for match in domain_pattern.finditer(text):
        domain_value = match.group(0)
        tld = str(match.group(1) or "").lower()
        if tld in _NON_DOMAIN_SUFFIXES:
            continue
        labels = [part.strip().lower() for part in domain_value.split(".") if part.strip()]
        if any(label in _NON_DOMAIN_TOKENS for label in labels):
            continue
        if labels and labels[0] == "this":
            continue
        next_char = text[match.end()] if match.end() < len(text) else ""
        if next_char and (next_char.isdigit() or next_char in {"_", "-", "\\"}):
            # Avoid truncation artifacts like ".ps" from ".ps1" file names.
            continue
        lowered = _normalize_ioc_value(domain_value).lower()
        if lowered.startswith("www.") and len(lowered) <= 4:
            continue
        if f"file:{lowered}" in seen:
            continue
        # Also skip when the matched domain is a strict prefix of a known file IOC.
        if any(key.startswith(f"file:{lowered}") for key in seen):
            continue
        add("domain", domain_value)

    if _looks_like_command_text(text):
        add("command", text)

    return out


def _collect_result_ioc_candidates(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    seen: set[str] = set()
    has_curated_iocs = False

    def push(
        value: Any,
        explicit_type: Optional[str],
        source_hint: str,
        evidence: Optional[str] = None,
        path: Optional[str] = None,
        context: Optional[str] = None,
    ) -> None:
        inferred = _infer_ioc_type(_normalize_ioc_value(value), explicit_type)
        if inferred not in _UI_ALLOWED_IOC_TYPES:
            return
        text = _normalize_curated_ioc_value(value, inferred)
        if not text or _is_noise_ioc_value(text, inferred):
            return
        if inferred == "file" and not _looks_like_file_path_ioc(text):
            return
        if inferred == "command" and not _looks_like_command_text(text):
            return
        key = f"{inferred}:{text.lower()}"
        if key in seen:
            return
        seen.add(key)
        normalized_path = _normalize_ioc_value(path)
        if inferred == "file" and not normalized_path:
            normalized_path = text
        candidates.append(
            {
                "value": text,
                "type": inferred,
                "source_hint": source_hint,
                "evidence": _normalize_ioc_value(evidence, max_len=180) if evidence else None,
                "path": normalized_path if inferred == "file" else None,
                "context": _normalize_ioc_value(context, max_len=280) if context else None,
            }
        )

    raw_result = result.get("raw_result") if isinstance(result.get("raw_result"), dict) else {}
    curated_rows = raw_result.get("curated_iocs") if isinstance(raw_result, dict) else None
    if isinstance(curated_rows, list):
        has_curated_iocs = False
        for row in curated_rows:
            if isinstance(row, dict):
                push(
                    row.get("value") or row.get("indicator") or row.get("ioc"),
                    row.get("type") or row.get("ioc_type"),
                    "curated_iocs",
                    row.get("evidence"),
                    row.get("path") or row.get("file_path"),
                    row.get("context") or row.get("reason"),
                )
                has_curated_iocs = has_curated_iocs or bool(candidates)
            else:
                push(row, None, "curated_iocs")
                has_curated_iocs = has_curated_iocs or bool(candidates)

    extracted = result.get("extracted_iocs", {}) if isinstance(result.get("extracted_iocs"), dict) else {}
    for bucket_type, values in extracted.items():
        if not isinstance(values, list):
            continue
        explicit_type = str(bucket_type or "").strip().lower() or None
        for item in values:
            if isinstance(item, dict):
                indicator_value = (
                    item.get("value")
                    or item.get("indicator")
                    or item.get("ioc")
                    or item.get("artifact")
                    or item.get("hash")
                    or item.get("path")
                    or item.get("file")
                    or item.get("command")
                    or item.get("script")
                )
                explicit_type = (
                    str(
                        item.get("ioc_type")
                        or item.get("type")
                        or item.get("indicator_type")
                        or explicit_type
                        or ""
                    ).strip().lower() or None
                )
                push(
                    indicator_value,
                    explicit_type,
                    "extracted_iocs",
                    path=item.get("path") or item.get("file_path"),
                    context=item.get("context"),
                )
            else:
                push(item, explicit_type, "extracted_iocs")

    request = result.get("request") if isinstance(result.get("request"), dict) else {}
    request_keys = {
        "domain": "domain",
        "domains": "domain",
        "fqdn": "domain",
        "url": "url",
        "uri": "url",
        "ip": "ip",
        "ip_address": "ip",
        "hash": "hash",
        "sha256": "hash",
        "sha1": "hash",
        "md5": "hash",
        "file": "file",
        "path": "file",
        "filename": "file",
        "command": "command",
        "script": "command",
        "powershell": "command",
    }
    for key, explicit_type in request_keys.items():
        if key not in request:
            continue
        value = request.get(key)
        if isinstance(value, list):
            for item in value:
                push(item, explicit_type, f"request:{key}")
        else:
            push(value, explicit_type, f"request:{key}")

    text_pool: List[str] = []

    def collect_strings(node: Any, depth: int = 0, limit: int = 220) -> None:
        if depth > 5 or len(text_pool) >= limit:
            return
        if isinstance(node, str):
            stripped = node.strip()
            if stripped:
                text_pool.append(stripped)
            return
        if isinstance(node, list):
            for child in node[:80]:
                collect_strings(child, depth + 1, limit)
            return
        if isinstance(node, dict):
            for _key, child in list(node.items())[:80]:
                collect_strings(child, depth + 1, limit)

    if not has_curated_iocs:
        if result.get("summary"):
            text_pool.append(str(result.get("summary")))
        if result.get("error"):
            text_pool.append(str(result.get("error")))
        findings = result.get("findings") if isinstance(result.get("findings"), list) else []
        for finding in findings[:80]:
            if not isinstance(finding, dict):
                continue
            for field in ("title", "detail", "description", "message"):
                if finding.get(field):
                    text_pool.append(str(finding.get(field)))

        if isinstance(raw_result, dict):
            for key in ("stdout", "stderr", "summary", "message", "detail", "output"):
                value = raw_result.get(key)
                if isinstance(value, str) and value.strip():
                    text_pool.append(value)
            collect_strings(raw_result)
        collect_strings(request)

        for blob in text_pool:
            for extracted_row in _extract_iocs_from_text(blob):
                push(extracted_row.get("value"), extracted_row.get("type"), "parsed_text")

    return candidates


def _collect_virustotal_lookup(meta: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}

    for wave in meta.get("waves", []) if isinstance(meta, dict) else []:
        for result in wave.get("action_results", []):
            tool_name = str(result.get("tool_name") or "").lower()
            if "virustotal" not in tool_name:
                continue

            raw_result = result.get("raw_result") if isinstance(result.get("raw_result"), dict) else {}
            for row in raw_result.get("results", []) if isinstance(raw_result.get("results"), list) else []:
                if not isinstance(row, dict):
                    continue
                parsed = _parse_vt_output(
                    row.get("output"),
                    indicator=row.get("indicator"),
                    indicator_type=row.get("type"),
                )
                parsed_type = _infer_ioc_type(parsed.get("indicator"), parsed.get("type"))
                if not _is_vt_eligible_ioc_type(parsed_type):
                    continue
                parsed["type"] = parsed_type
                key = str(parsed.get("indicator") or "").strip().lower()
                if key:
                    lookup[key] = parsed

            for finding in result.get("findings", []) if isinstance(result.get("findings"), list) else []:
                if not isinstance(finding, dict):
                    continue
                title = str(finding.get("title") or "")
                title_match = re.search(r"VT\s+([A-Za-z]+)\s+([^\s]+)", title)
                parsed = _parse_vt_output(
                    finding.get("detail"),
                    indicator=title_match.group(2) if title_match else None,
                    indicator_type=title_match.group(1) if title_match else None,
                )
                parsed_type = _infer_ioc_type(parsed.get("indicator"), parsed.get("type"))
                if not _is_vt_eligible_ioc_type(parsed_type):
                    continue
                parsed["type"] = parsed_type
                key = str(parsed.get("indicator") or "").strip().lower()
                if key and key not in lookup:
                    lookup[key] = parsed

    return lookup


def _extract_asset_context(meta: Dict[str, Any]) -> Dict[str, Any]:
    host_names: set[str] = set()
    ipv4_values: set[str] = set()
    ipv6_values: set[str] = set()
    os_names: set[str] = set()
    os_platforms: set[str] = set()
    user_values: set[str] = set()

    def add_host(value: Any) -> None:
        text = str(value or "").strip()
        if text and len(text) <= 128:
            host_names.add(text)

    def add_ip(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                add_ip(item)
            return
        text = str(value or "").strip()
        if not text:
            return
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
            ipv4_values.add(text)
            return
        if ":" in text:
            ipv6_values.add(text)

    def add_os_name(value: Any) -> None:
        text = str(value or "").strip()
        if text and len(text) <= 160:
            os_names.add(text)

    def add_os_platform(value: Any) -> None:
        text = str(value or "").strip().lower()
        if text and len(text) <= 64:
            os_platforms.add(text)

    def add_user(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                add_user(item)
            return
        text = str(value or "").strip()
        if not text:
            return
        if len(text) > 128:
            return
        lowered = text.lower()
        if lowered in {"n/a", "unknown", "-", "none", "null"}:
            return
        user_values.add(text)

    def scan(node: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, dict):
            for key, value in list(node.items())[:180]:
                key_l = str(key).lower()
                if key_l in {"host_name", "hostname", "computer_name", "device_name"}:
                    add_host(value)
                elif key_l == "host" and isinstance(value, str):
                    add_host(value)
                elif key_l in {"host_ip", "ip", "source_ip", "destination_ip", "remote_ip", "local_ip"}:
                    add_ip(value)
                elif key_l in {"host_os_name", "os_name", "operating_system", "os"}:
                    add_os_name(value)
                elif key_l in {"host_os_platform", "os_platform", "platform"}:
                    add_os_platform(value)
                elif key_l in {"user", "username", "user_name", "user_id", "account_name", "principal", "target_user_name"}:
                    add_user(value)
                scan(value, depth + 1)
            return
        if isinstance(node, list):
            for item in node[:220]:
                scan(item, depth + 1)

    scan(meta.get("plans", []) if isinstance(meta, dict) else [])
    scan(meta.get("waves", []) if isinstance(meta, dict) else [])

    host_name = sorted(host_names)[0] if host_names else None
    host_ip = sorted(ipv4_values)[0] if ipv4_values else (sorted(ipv6_values)[0] if ipv6_values else None)
    os_name = sorted(os_names)[0] if os_names else None
    os_platform = sorted(os_platforms)[0] if os_platforms else None
    alerted_user = None
    if user_values:
        def user_rank(value: str) -> int:
            text = str(value or "").strip()
            lowered = text.lower()
            if re.fullmatch(r"s-\d-\d+(?:-\d+)+", lowered):
                return 0
            if lowered in {"system", "local service", "network service", "s-1-5-18", "s-1-5-19", "s-1-5-20"}:
                return 0
            if "\\" in text or "@" in text:
                return 4
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9._-]{1,63}", text):
                return 5
            return 2

        alerted_user = sorted(user_values, key=lambda value: (-user_rank(value), len(value), value.lower()))[0]
        if user_rank(alerted_user) <= 1:
            alerted_user = None
        elif host_name and alerted_user and alerted_user.lower() == str(host_name).lower():
            alerted_user = None

    os_fingerprint = f"{os_name or ''} {os_platform or ''}".strip().lower()
    if not os_fingerprint:
        device_type = "Unknown"
    elif "server" in os_fingerprint:
        device_type = "Server"
    elif any(token in os_fingerprint for token in ("ios", "android")):
        device_type = "Mobile"
    else:
        device_type = "Endpoint"

    return {
        "host_name": host_name,
        "host_ip": host_ip,
        "all_host_ips": sorted(ipv4_values) + sorted(ipv6_values),
        "os_name": os_name,
        "os_platform": os_platform,
        "device_type": device_type,
        "alerted_user": alerted_user,
    }


def _infer_ioc_type(indicator: str, fallback_type: Optional[str] = None) -> str:
    value = _normalize_ioc_value(indicator)
    detected = str(fallback_type or "").strip().lower()
    if not value:
        return "default"

    lowered = value.lower()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return "url"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return "email"
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", value):
        return "hash"
    if _looks_like_command_text(value):
        return "command"
    if "\\" in value or "/" in value:
        return "file"
    ext_match = re.search(r"\.([a-z0-9]{1,10})$", value, flags=re.IGNORECASE)
    if ext_match:
        file_ext = ext_match.group(1).lower()
        if file_ext in {
            "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
            "zip", "rar", "7z", "exe", "dll", "sys", "bat", "ps1", "vbs", "js",
            "doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "tmp", "dat", "bin",
        }:
            return "file"
    domain_match = re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,10})",
        lowered,
    )
    domain_is_valid = False
    if domain_match:
        tld = str(domain_match.group(1) or "").lower()
        labels = [part.strip().lower() for part in lowered.split(".") if part.strip()]
        if (
            tld not in _NON_DOMAIN_SUFFIXES
            and not any(label in _NON_DOMAIN_TOKENS for label in labels)
            and not (labels and labels[0] == "this")
        ):
            domain_is_valid = True
            return "domain"

    if detected == "ip" and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if detected == "url" and (lowered.startswith("http://") or lowered.startswith("https://")):
        return "url"
    if detected == "email" and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return "email"
    if detected == "hash" and re.fullmatch(r"[a-fA-F0-9]{32,128}", value):
        return "hash"
    if detected == "file" and _looks_like_file_path_ioc(value):
        return "file"
    if detected == "command" and _looks_like_command_text(value):
        return "command"
    if detected == "domain" and domain_is_valid:
        return detected
    return "default"


def _build_evidence_summary(meta: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    if not events:
        return "No evidence events captured for this case yet."

    category_counts: Dict[str, int] = {}
    for item in events:
        category = str(item.get("category") or "info").strip().lower()
        category_counts[category] = category_counts.get(category, 0) + 1

    ordered = []
    for key in ("execution", "network", "auth", "email", "file", "lateral", "persistence", "info"):
        if category_counts.get(key):
            ordered.append(f"{key}: {category_counts[key]}")
    if not ordered:
        ordered = [f"events: {len(events)}"]

    return _shorten_detail(
        f"Incident timeline contains {len(events)} deduplicated events in chronological order ({', '.join(ordered)}).",
        max_len=420,
    )


def _extract_alert_details(meta: Dict[str, Any], ticket: Dict[str, Any]) -> Dict[str, Any]:
    description_candidates: List[tuple[int, str]] = []
    tags: set[str] = set()
    source_candidates: List[str] = []
    created_candidates: List[str] = []
    assignee_candidates: List[str] = []

    def add_description(value: Any, weight: int = 1) -> None:
        text = _normalize_ioc_value(value, max_len=1800)
        if not text or len(text) < 12:
            return
        lowered = text.lower()
        if lowered.startswith("creating scriptblock text"):
            return
        if "scriptblock text (1 of 1)" in lowered:
            return
        if _looks_like_structured_text(text):
            return
        description_candidates.append((weight, text))

    def add_tags(value: Any) -> None:
        if isinstance(value, list):
            for item in value[:80]:
                add_tags(item)
            return
        text = _normalize_ioc_value(value, max_len=80)
        if not text:
            return
        lowered = text.lower()
        if lowered in {"unknown", "none", "null", "-", "n/a"}:
            return
        if len(text) > 48:
            return
        tags.add(text)

    def add_source(value: Any) -> None:
        text = _normalize_ioc_value(value, max_len=120)
        if not text:
            return
        lowered = text.lower()
        if lowered in {"unknown", "none", "null", "-", "n/a"}:
            return
        source_candidates.append(text)

    def add_created(value: Any) -> None:
        text = str(value or "").strip()
        if not text:
            return
        if _safe_iso_datetime(text):
            created_candidates.append(text)

    def add_assignee(value: Any) -> None:
        text = _normalize_ioc_value(value, max_len=120)
        if not text:
            return
        lowered = text.lower()
        if lowered in {"unknown", "none", "null", "-", "n/a"}:
            return
        assignee_candidates.append(text)

    def scan(node: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in list(node.items())[:220]:
                key_l = str(key).lower()
                if key_l in {"rule_description", "alert_reason"}:
                    add_description(value, weight=5)
                elif key_l in {"description"}:
                    add_description(value, weight=4)
                elif key_l in {"message"}:
                    add_description(value, weight=3)
                elif key_l in {"rule_name", "alert_name"}:
                    add_tags(value)
                elif key_l in {"tags", "rule_tags", "threat_tags", "labels", "alert_tags"}:
                    add_tags(value)
                elif key_l in {"event_dataset", "event_provider", "source", "provider"}:
                    add_source(value)
                elif key_l in {"event_created", "@timestamp", "timestamp", "created_at"}:
                    add_created(value)
                elif key_l in {"assignee", "owner", "analyst", "assigned_to"}:
                    add_assignee(value)
                scan(value, depth + 1)
            return
        if isinstance(node, list):
            for item in node[:180]:
                scan(item, depth + 1)

    scan(meta)

    description = ""
    if description_candidates:
        description = sorted(description_candidates, key=lambda row: (row[0], len(row[1])), reverse=True)[0][1]
    if not description:
        description = str(ticket.get("summary") or "").strip() or str(ticket.get("title") or "").strip()
    if not description:
        description = "No alert description available."

    selected_source = "siem"
    if source_candidates:
        selected_source = sorted(source_candidates, key=lambda value: (0 if "." in value else 1, len(value), value.lower()))[0]

    selected_created = ticket.get("created_at")
    if created_candidates:
        parsed_created = sorted(
            ((value, _safe_iso_datetime(value)) for value in created_candidates),
            key=lambda item: item[1] or datetime.max.replace(tzinfo=timezone.utc),
        )
        selected_created = parsed_created[0][0]

    selected_tags = sorted(tags, key=lambda value: (len(value), value.lower()))[:10]

    return {
        "source": selected_source,
        "assignee": assignee_candidates[0] if assignee_candidates else None,
        "created_at": selected_created,
        "description": description,
        "tags": selected_tags,
        "alert_id": ticket.get("alert_id"),
    }


def _display_ioc_value(ioc_type: str, value: str, path_value: Optional[str]) -> str:
    normalized_value = _normalize_ioc_value(value, max_len=260)
    if ioc_type != "file":
        return normalized_value
    raw_path = _normalize_ioc_value(path_value or value, max_len=1000)
    if not raw_path:
        return normalized_value
    parts = re.split(r"[\\/]+", raw_path)
    file_name = parts[-1].strip() if parts else ""
    if file_name:
        return _normalize_ioc_value(file_name, max_len=180)
    return normalized_value


def _default_ioc_context(candidate: Dict[str, Any], ioc_type: str, value: str) -> str:
    raw_source_hint = str(candidate.get("source_hint") or "").strip()
    source_hint = raw_source_hint.replace("_", " ").strip()
    if raw_source_hint.startswith("request:"):
        source_hint = "orchestrator request context"
    if raw_source_hint == "curated_iocs":
        source_hint = "SIEM curated IOC selection"
    elif raw_source_hint == "extracted_iocs":
        source_hint = "specialist extraction output"
    elif raw_source_hint == "parsed_text":
        source_hint = "event message parsing"
    if not source_hint:
        source_hint = "telemetry review"

    relevance = {
        "ip": "This network endpoint is directly tied to the alert execution path.",
        "domain": "This domain appears in the alert telemetry and may represent external communication.",
        "url": "This URL was observed in the triggering activity and supports analyst validation.",
        "hash": "This hash identifies a concrete file artifact for external reputation checks.",
        "file": "This file path identifies an on-host artifact tied to the alert behavior.",
        "command": "This command line captures execution behavior that explains the alert trigger.",
    }.get(ioc_type, "This artifact provides supporting context for triage.")

    evidence = _normalize_ioc_value(candidate.get("evidence"), max_len=180)
    context = f"Found in {source_hint}. {relevance}"
    if evidence:
        context = f"{context} Evidence: {evidence}"
    return _normalize_ioc_value(context, max_len=320)


def _normalize_timeline_detail(value: Any) -> str:
    text = _normalize_ioc_value(value, max_len=900)
    if not text:
        return ""
    text = re.sub(r"(?i)^creating\s+scriptblock\s+text\s*\(1\s+of\s+1\)\s*:\s*", "", text)
    text = re.sub(r"(?i)\bscriptblock\s*id\s*:\s*[0-9a-f\-]{8,}", "", text)
    text = re.sub(r"(?i)\bpath\s*:\s*$", "", text).strip()
    text = re.sub(r"\s{2,}", " ", text).strip(" ;,")
    if not text:
        return ""
    if text.startswith("{") and text.endswith("}"):
        return ""
    lower = text.lower()
    if lower in {"prompt", "-", "null", "none", "0"}:
        return ""

    if any(
        marker in lower
        for marker in (
            "__cmdletization_",
            "set-strictmode",
            "errorcategory_message",
            "origininfo",
            "psmessagedetails",
            "innerexception",
            "$global:?",
            "$this.exception",
            "prefixorigin",
        )
    ):
        return ""

    if "invoke-webrequest" in lower or " iwr " in lower:
        return _shorten_detail(text, max_len=260)
    if "invoke-atomictest" in lower:
        return _shorten_detail(text, max_len=260)
    if "new-smbmapping" in lower or ("net use" in lower and "\\\\" in text):
        return _shorten_detail(text, max_len=260)
    if "telnet_client.exe" in lower:
        return _shorten_detail(text, max_len=260)
    if "stop-executionlog" in lower:
        return _shorten_detail(text, max_len=260)

    return _shorten_detail(text, max_len=260)


def _extract_command_from_event_text(value: Any) -> str:
    text = _normalize_ioc_value(value, max_len=2200)
    if not text:
        return ""
    stripped = text

    scriptblock_match = re.search(
        r"(?i)creating\s+scriptblock\s+text\s*\(1\s+of\s+1\)\s*:\s*(.+?)(?:\s+scriptblockid\s*:|\s+path\s*:|$)",
        stripped,
    )
    if scriptblock_match:
        stripped = scriptblock_match.group(1).strip()

    stripped = re.sub(r"(?i)\bscriptblock\s*id\s*:\s*[0-9a-f\-]{8,}", "", stripped)
    stripped = re.sub(r"(?i)\bpath\s*:\s*$", "", stripped).strip(" ;,")
    stripped = re.sub(r"\s{2,}", " ", stripped).strip()
    lowered = stripped.lower()
    if not stripped or lowered in {"0", "-", "null", "none"}:
        return ""
    if any(
        marker in lowered
        for marker in (
            "__cmdletization_",
            "set-strictmode",
            "errorcategory_message",
            "origininfo",
            "psmessagedetails",
            "innerexception",
            "$global:?",
            "$this.exception",
            "prefixorigin",
        )
    ):
        return ""
    if len(stripped) < 8:
        return ""
    return _shorten_detail(stripped, max_len=1200)


def _event_sort_key(timestamp: Any) -> tuple:
    raw = str(timestamp or "").strip()
    if not raw:
        return (datetime.max.replace(tzinfo=timezone.utc), "~")

    parsed = _safe_iso_datetime(raw)
    if parsed:
        return (parsed, raw)

    fallback_formats = (
        "%m/%d/%Y, %I:%M:%S %p",
        "%m/%d/%Y, %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
    )
    for fmt in fallback_formats:
        try:
            parsed_local = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            return (parsed_local, raw)
        except ValueError:
            continue
    return (datetime.max.replace(tzinfo=timezone.utc), raw)


def _classify_timeline_action(raw_action: Any, detail: Any) -> tuple[str, str]:
    action_text = _normalize_ioc_value(raw_action, max_len=120).replace("_", " ").strip()
    detail_text = _normalize_ioc_value(detail, max_len=600)
    combined = f"{action_text} {detail_text}".lower()

    def has_any(*tokens: str) -> bool:
        return any(token in combined for token in tokens)

    if has_any("powershell", "scriptblock", "invoke-webrequest", "encodedcommand", "pwsh", "iex ", "iwr "):
        return ("PowerShell Script Event", "script")
    if has_any("remote command", "invoke-command", "winrm", "psexec", "wmic", "smbmapping", "net use ", "telnet"):
        return ("Remote Command Event", "command")
    if has_any("sign-in", "signin", "logon", "authentication", "credential", "mfa"):
        return ("Sign-In Event", "signin")
    if has_any("email", "mail", "smtp", "phish", "inbox"):
        return ("Email Event", "email")
    if has_any("dns", "domain lookup", "resolve", "query name"):
        return ("DNS Query Event", "dns")
    if has_any("http", "https", "url", "webrequest", "c2", "outbound", "socket", "port "):
        return ("Network Request Event", "network")
    if has_any("file", "archive", "zip", "download", "upload", "write", "created", "delete"):
        return ("File System Event", "file")
    if has_any("registry", "hklm", "hkcu", "reg add", "reg set"):
        return ("Registry Event", "registry")
    if has_any("service", "scheduled task", "schtasks", "autorun", "startup"):
        return ("Persistence Event", "persistence")

    if action_text:
        label = re.sub(r"\s+", " ", action_text).strip().title()
        return (_shorten_detail(label, max_len=64), "info")
    return ("Observed Event", "info")


def _build_incident_timeline(raw_events: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    collapsed: Dict[str, Dict[str, Any]] = {}

    for event in raw_events:
        timestamp = event.get("timestamp")
        host = _normalize_ioc_value(event.get("host"), max_len=140) or None
        raw_detail = event.get("description") or event.get("detail") or ""
        detail = _normalize_timeline_detail(raw_detail)
        if not detail:
            detail = _normalize_timeline_detail(event.get("summary") or "")
        if not detail:
            continue

        action_label, category = _classify_timeline_action(event.get("event") or event.get("action"), detail)
        canonical_detail = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", detail.lower())
        signature = "|".join(
            [
                host.lower() if host else "",
                action_label.lower(),
                canonical_detail,
            ]
        )
        sort_dt, _ = _event_sort_key(timestamp)

        if signature in collapsed:
            current = collapsed[signature]
            current["duplicate_count"] = int(current.get("duplicate_count") or 1) + 1
            if sort_dt < current.get("_sort_dt", sort_dt):
                current["_sort_dt"] = sort_dt
                current["timestamp"] = timestamp
            samples = current.get("samples")
            if not isinstance(samples, list):
                samples = []
                current["samples"] = samples
            for candidate in (
                _extract_command_from_event_text(event.get("command")),
                _extract_command_from_event_text(raw_detail),
                _extract_command_from_event_text(event.get("raw_message")),
            ):
                if candidate and candidate not in samples:
                    samples.append(candidate)
                    if len(samples) >= 8:
                        break
            continue

        preview_text = _shorten_detail(detail, max_len=180)
        samples: List[str] = []
        for candidate in (
            _extract_command_from_event_text(event.get("command")),
            _extract_command_from_event_text(raw_detail),
            _extract_command_from_event_text(event.get("raw_message")),
        ):
            if candidate and candidate not in samples:
                samples.append(candidate)
                if len(samples) >= 8:
                    break

        collapsed[signature] = {
            "timestamp": timestamp,
            "event": action_label,
            "category": category,
            "host": host,
            "description": preview_text or "Observed related activity.",
            "full_detail": samples[0] if samples else (detail or preview_text or "Observed related activity."),
            "samples": samples,
            "duplicate_count": 1,
            "_sort_dt": sort_dt,
        }

    timeline = list(collapsed.values())
    timeline.sort(key=lambda item: (item.get("_sort_dt", datetime.max.replace(tzinfo=timezone.utc)), str(item.get("event") or "")))
    for item in timeline:
        item.pop("_sort_dt", None)
    return timeline[:limit]


def _build_case_overview(ticket: Dict[str, Any]) -> Dict[str, Any]:
    meta = _load_run_metadata(ticket)
    triage_journal = _build_triage_journal(ticket)
    iocs: List[Dict[str, Any]] = []
    raw_events: List[Dict[str, Any]] = []
    seen_iocs = set()
    source_tools = set()
    vt_lookup = _collect_virustotal_lookup(meta)
    asset_context = _extract_asset_context(meta)
    alert_details = _extract_alert_details(meta, ticket)
    pipeline_score = _resolve_pipeline_score(meta)
    runtime_seconds = _pipeline_runtime_seconds(meta)

    for wave in meta.get("waves", []) if isinstance(meta, dict) else []:
        wave_timestamp = wave.get("completed_at") or wave.get("started_at")
        for result in wave.get("action_results", []):
            source_tool = str(result.get("tool_name", "")).strip()
            if source_tool:
                source_tools.add(source_tool)
            raw_result = result.get("raw_result") if isinstance(result.get("raw_result"), dict) else {}
            request = result.get("request") if isinstance(result.get("request"), dict) else {}
            host_name = request.get("host_name") or request.get("host") or ""

            if source_tool == "siem_specialist":
                parsed_rows = raw_result.get("parsed_results") if isinstance(raw_result, dict) else None
                if isinstance(parsed_rows, list):
                    for parsed in parsed_rows[:12]:
                        if not isinstance(parsed, dict):
                            continue
                        key_events = parsed.get("key_events")
                        if not isinstance(key_events, list):
                            continue
                        for key_event in key_events[:30]:
                            if not isinstance(key_event, dict):
                                continue
                            raw_events.append(
                                {
                                    "timestamp": key_event.get("timestamp") or key_event.get("@timestamp") or wave_timestamp,
                                    "event": key_event.get("event_action") or key_event.get("event_type") or key_event.get("action") or "event",
                                    "host": (
                                        key_event.get("host_name")
                                        or key_event.get("source_host")
                                        or key_event.get("computer_name")
                                        or host_name
                                        or asset_context.get("host_name")
                                    ),
                                    "description": key_event.get("message") or key_event.get("detail") or "",
                                    "raw_message": key_event.get("message") or "",
                                    "command": (
                                        key_event.get("process_command_line")
                                        or key_event.get("command_line")
                                        or key_event.get("process")
                                        or ""
                                    ),
                                    "source_tool": source_tool,
                                }
                            )

            if source_tool == "entra_specialist":
                signins = raw_result.get("events") if isinstance(raw_result, dict) else None
                if isinstance(signins, list):
                    for signin in signins[:40]:
                        if not isinstance(signin, dict):
                            continue
                        status = str(signin.get("status") or "unknown").strip()
                        user_name = str(signin.get("userPrincipalName") or signin.get("userId") or "").strip()
                        app_name = str(signin.get("appDisplayName") or "").strip()
                        ip_address = str(signin.get("ipAddress") or "").strip()
                        detail_parts = []
                        if user_name:
                            detail_parts.append(f"user {user_name}")
                        if app_name:
                            detail_parts.append(f"app {app_name}")
                        if ip_address:
                            detail_parts.append(f"ip {ip_address}")
                        detail_parts.append(f"status {status}")
                        raw_events.append(
                            {
                                "timestamp": signin.get("createdDateTime") or wave_timestamp,
                                "event": "sign_in",
                                "host": host_name or asset_context.get("host_name"),
                                "description": ", ".join(detail_parts),
                                "source_tool": source_tool,
                            }
                        )

            for candidate in _collect_result_ioc_candidates(result):
                value_text = _normalize_ioc_value(candidate.get("value"))
                inferred_type = _infer_ioc_type(value_text, candidate.get("type"))
                if not value_text or inferred_type not in _UI_ALLOWED_IOC_TYPES:
                    continue
                if (
                    inferred_type == "hash"
                    and str(ticket.get("alert_id") or "").strip()
                    and value_text.lower() == str(ticket.get("alert_id") or "").strip().lower()
                ):
                    continue

                normalized = (inferred_type, value_text.lower())
                if normalized in seen_iocs:
                    continue
                seen_iocs.add(normalized)

                vt = vt_lookup.get(normalized[1], {})
                vt_eligible = _is_vt_eligible_ioc_type(inferred_type)
                has_vt = vt_eligible and isinstance(vt, dict) and (
                    vt.get("verdict") is not None
                    or vt.get("score") is not None
                    or vt.get("stats") is not None
                )
                file_path = candidate.get("path")
                if inferred_type == "file" and not file_path:
                    file_path = value_text
                display_value = _display_ioc_value(inferred_type, value_text, file_path)
                context_text = _normalize_ioc_value(candidate.get("context"), max_len=320)
                if not context_text:
                    context_text = _default_ioc_context(candidate, inferred_type, value_text)
                ioc_row: Dict[str, Any] = {
                    "type": inferred_type,
                    "value": value_text,
                    "display_value": display_value,
                    "path": file_path,
                    "evidence": candidate.get("evidence"),
                    "context": context_text,
                    "source_tool": source_tool,
                    "source_hint": candidate.get("source_hint"),
                    "source": (vt.get("source") if has_vt else None) or source_tool,
                    "virustotal_checked": bool(has_vt),
                    "virustotal_eligible": vt_eligible,
                    "virustotal_verdict": vt.get("verdict") if has_vt else ("unknown" if vt_eligible else None),
                    "virustotal_stats": vt.get("stats") if has_vt else None,
                }
                if has_vt:
                    ioc_row.update(
                        {
                            "threat_score": vt.get("score"),
                        }
                        )
                iocs.append(ioc_row)

    events = _build_incident_timeline(raw_events, limit=24)
    ioc_type_order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "file": 4, "command": 5}
    iocs = sorted(
        iocs,
        key=lambda item: (
            ioc_type_order.get(str(item.get("type")), 99),
            -(item.get("threat_score") or -1),
            str(item.get("value") or ""),
        ),
    )[:16]
    evidence_summary = _build_evidence_summary(meta, events)
    confidence = meta.get("confidence") if isinstance(meta, dict) else None
    pipeline_confidence_score = _resolve_pipeline_score(meta)
    journal_summary: Optional[str] = None
    journal_summary_full: Optional[str] = None
    for step in reversed(triage_journal):
        finding = step.get("finding")
        candidate = _extract_narrative_from_value(finding)
        if not candidate:
            candidate = _extract_narrative_from_value(step.get("action"))
        if candidate:
            journal_summary_full = candidate.strip()
            journal_summary = _shorten_detail(journal_summary_full, max_len=380)
            break

    summary_full = (
        str(ticket.get("summary") or "").strip()
        or journal_summary_full
        or evidence_summary
        or "No analyst close note is saved yet. Use evidence and timeline to complete triage."
    )
    summary_short = _shorten_detail(summary_full, max_len=380)

    decision_score = _resolve_decision_risk_score(ticket, triage_journal)
    decision_confidence_score = _resolve_decision_confidence_score(ticket, triage_journal)
    decision_action = _resolve_decision_action(ticket, triage_journal)
    # Decision confidence represents model confidence in classification.
    # Keep operational/pipeline confidence separate.
    resolved_confidence_score = decision_confidence_score
    resolved_risk_score = (
        decision_score
        if decision_score is not None
        else pipeline_score
        if pipeline_score is not None
        else ticket.get("risk_score")
    )
    if resolved_confidence_score is None and pipeline_confidence_score is not None:
        resolved_confidence_score = pipeline_confidence_score
    if (
        isinstance(resolved_confidence_score, (int, float))
        and isinstance(resolved_risk_score, (int, float))
        and abs(float(resolved_confidence_score) - float(resolved_risk_score)) < 0.05
    ):
        if (
            isinstance(pipeline_confidence_score, (int, float))
            and abs(float(pipeline_confidence_score) - float(resolved_risk_score)) >= 0.05
        ):
            resolved_confidence_score = float(pipeline_confidence_score)
        else:
            resolved_confidence_score = None
    effective_severity = _severity_from_risk_score(resolved_risk_score, ticket.get("severity"))
    resolved_action = decision_action or ticket.get("action") or ticket.get("verdict")
    return {
        "summary": summary_short,
        "summary_full": summary_full,
        "investigation_summary": journal_summary_full or summary_full,
        "classification": ticket.get("classification") or "unclassified",
        "action": resolved_action or "pending",
        "verdict": resolved_action or "pending",
        "pipeline_score": pipeline_score,
        "pipeline_runtime_seconds": runtime_seconds,
        "pipeline_confidence": _compact_for_display(confidence),
        "pipeline_confidence_score": pipeline_confidence_score,
        "operational_confidence_score": pipeline_confidence_score,
        "decision_confidence_score": decision_confidence_score,
        "confidence_score": resolved_confidence_score,
        "confidence_rationale": confidence.get("rationale") if isinstance(confidence, dict) else None,
        "alert_risk_score": ticket.get("risk_score"),
        "decision_risk_score": decision_score,
        "risk_score": resolved_risk_score,
        "effective_severity": effective_severity,
        "source_tools": sorted(source_tools),
        "asset_context": asset_context,
        "alert_details": alert_details,
        "evidence_summary": evidence_summary,
        "iocs": iocs,
        "events": events,
        "triage_journal": triage_journal,
    }


def _compact_for_display(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "<truncated-depth>"
    if isinstance(value, str):
        text = value.strip()
        if len(text) > 1200:
            return text[:1200] + "...<truncated>"
        return text
    if isinstance(value, list):
        compacted = [_compact_for_display(item, depth + 1) for item in value[:30]]
        return [item for item in compacted if item not in ("", None, [], {})]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in list(value.items())[:60]:
            compact_item = _compact_for_display(item, depth + 1)
            if compact_item in ("", None, [], {}):
                continue
            out[key] = compact_item
        return out
    return value


def _to_pretty_json(value: Any) -> str:
    compacted = _compact_for_display(value)
    if isinstance(compacted, str):
        return compacted
    try:
        return json.dumps(compacted, indent=2, ensure_ascii=False)
    except Exception:
        return str(compacted)


def _build_audit_graph(agent_entries: List[Dict[str, Any]], run_meta: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    details: Dict[str, Any] = {}
    node_index: Dict[str, Dict[str, Any]] = {}
    ordered_agent_ids: List[str] = []
    tool_nodes_by_wave: Dict[int, List[str]] = {}
    waves = run_meta.get("waves", []) if isinstance(run_meta, dict) else []
    has_tool_results = any((wave.get("action_results") or []) for wave in waves)

    def add_node(
        node_id: str,
        *,
        name: str,
        node_type: str,
        worker: Optional[int] = None,
        duration_ms: Optional[int] = None,
        input_data: Any = None,
        output_data: Any = None,
        record_count: int = 1,
        summary: str = "",
    ) -> None:
        if node_id in node_index:
            existing = node_index[node_id]
            existing["record_count"] = int(existing.get("record_count", 1)) + max(1, int(record_count or 1))
            return

        details[node_id] = {
            "summary": summary,
            "records": [
                {
                    "input": _compact_for_display(input_data),
                    "output": _compact_for_display(output_data),
                    "duration_ms": duration_ms,
                }
            ],
        }

        node = {
            "id": node_id,
            "name": name,
            "label": name,  # compatibility
            "node_type": node_type,
            "type": node_type,  # compatibility
            "worker": worker,
            "record_count": max(1, int(record_count or 1)),
            "duration_ms": duration_ms,
            "input_data": _to_pretty_json(input_data),
            "output_data": _to_pretty_json(output_data),
            "parent_id": None,
            "row": 0,
            "col": 0,
        }
        nodes.append(node)
        node_index[node_id] = node

    for entry in agent_entries:
        agent_name = str(entry.get("agent_name") or "UnknownAgent")
        agent_name_lower = agent_name.lower()
        is_specialist = agent_name_lower.endswith("_specialist") or "specialist" in agent_name_lower
        if has_tool_results and is_specialist:
            # Tool specialists are represented from canonical run metadata action results.
            continue

        input_payload = entry.get("input") if isinstance(entry.get("input"), dict) else {}
        output_payload = entry.get("output") if isinstance(entry.get("output"), dict) else {}

        wave = input_payload.get("wave")
        wave_num = int(wave) if isinstance(wave, (int, float)) else None
        node_id = f"agent:{agent_name}:w{wave_num}" if wave_num else f"agent:{agent_name}"
        node_name = f"{agent_name} W{wave_num}" if wave_num else agent_name

        add_node(
            node_id,
            name=node_name,
            node_type="agent",
            worker=wave_num,
            input_data=input_payload,
            output_data=output_payload,
            record_count=1,
            summary=f"{agent_name} execution",
        )
        if not ordered_agent_ids or ordered_agent_ids[-1] != node_id:
            ordered_agent_ids.append(node_id)

    for idx in range(1, len(ordered_agent_ids)):
        prev_id = ordered_agent_ids[idx - 1]
        curr_id = ordered_agent_ids[idx]
        node_index[curr_id]["parent_id"] = prev_id
        edges.append({"from": prev_id, "to": curr_id})

    for wave in waves:
        wave_num = int(wave.get("wave") or 0)
        orchestrator_id = f"agent:SOCAnalystOrchestrator:w{wave_num}" if wave_num else "agent:SOCAnalystOrchestrator"
        parent_for_tools = orchestrator_id if orchestrator_id in node_index else (ordered_agent_ids[-1] if ordered_agent_ids else None)

        for idx, result in enumerate(wave.get("action_results", []), start=1):
            action_id = str(result.get("action_id") or f"w{wave_num}_a{idx}")
            tool_name = str(result.get("tool_name") or "tool")
            findings = result.get("findings") if isinstance(result.get("findings"), list) else []

            node_id = f"tool:{action_id}"
            add_node(
                node_id,
                name=f"{tool_name}{f' W{wave_num}' if wave_num else ''}",
                node_type="tool",
                worker=wave_num or None,
                duration_ms=result.get("duration_ms"),
                input_data=result.get("request"),
                output_data={
                    "status": result.get("status"),
                    "summary": result.get("summary"),
                    "findings": result.get("findings"),
                    "raw_result": result.get("raw_result"),
                    "error": result.get("error"),
                },
                record_count=len(findings) or 1,
                summary=str(result.get("summary") or ""),
            )

            if parent_for_tools:
                node_index[node_id]["parent_id"] = parent_for_tools
                edges.append({"from": parent_for_tools, "to": node_id})

            tool_nodes_by_wave.setdefault(wave_num, []).append(node_id)

    main_row = 2
    for col, node_id in enumerate(ordered_agent_ids):
        if node_id not in node_index:
            continue
        node_index[node_id]["col"] = col
        node_index[node_id]["row"] = main_row

    for wave_num, node_ids in sorted(tool_nodes_by_wave.items(), key=lambda item: item[0]):
        orchestrator_id = f"agent:SOCAnalystOrchestrator:w{wave_num}" if wave_num else "agent:SOCAnalystOrchestrator"
        parent_col = node_index.get(orchestrator_id, {}).get("col", 0)
        col = parent_col + 1

        total = len(node_ids)
        start_row = max(0, main_row - (total // 2))
        for idx, node_id in enumerate(node_ids):
            node_index[node_id]["col"] = col
            node_index[node_id]["row"] = start_row + idx

    # Keep terminal decision agent to the right of tool fan-out columns.
    max_tool_col = max((node.get("col", 0) for node in nodes if node.get("node_type") == "tool"), default=0)
    for node in nodes:
        node_name = str(node.get("name") or "")
        if node_name.startswith("SOC2DecisionAgent") and int(node.get("col", 0)) <= max_tool_col:
            node["col"] = max_tool_col + 1

    if not nodes:
        return {"nodes": [], "edges": [], "details": {}}

    return {"nodes": nodes, "edges": edges, "details": details}


def _status_label(status: Optional[str]) -> str:
    value = (status or "").strip().lower()
    mapping = {
        "to_do": "To Do",
        "in_progress": "In Progress",
        "done": "Done",
    }
    return mapping.get(value, status or "Unknown")


def _normalize_severity_value(severity: Any) -> str:
    value = str(severity or "").strip().lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "unknown"


def _severity_from_risk_score(score: Any, fallback: Any = "unknown") -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return _normalize_severity_value(fallback)
    if value >= 80:
        return "critical"
    if value >= 60:
        return "high"
    if value >= 40:
        return "medium"
    return "low"


def _build_jira_payload_preview(ticket: Dict[str, Any], case_overview: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    description = (
        str((case_overview or {}).get("summary") or "").strip()
        or str(ticket.get("summary") or "").strip()
        or "SOC UI ticket update"
    )
    resolved_verdict = None
    if isinstance(case_overview, dict):
        resolved_verdict = case_overview.get("verdict") or case_overview.get("action")
    if not resolved_verdict:
        resolved_verdict = ticket.get("verdict") or ticket.get("action") or ""

    extracted_risk_score: Optional[float] = None
    if isinstance(case_overview, dict):
        for key in ("decision_risk_score", "risk_score"):
            candidate = case_overview.get(key)
            if isinstance(candidate, (int, float)):
                extracted_risk_score = float(candidate)
                break
            score = _extract_score_from_text(candidate)
            if score is not None:
                extracted_risk_score = score
                break
    if extracted_risk_score is None:
        extracted_risk_score = _resolve_decision_risk_score(
            ticket,
            case_overview.get("triage_journal") if isinstance(case_overview, dict) else None,
        )
    if extracted_risk_score is None:
        extracted_risk_score = _extract_score_from_value(ticket.get("risk_score"))
    return {
        "issue_key": ticket.get("jira_issue_key") or ticket.get("ticket_key"),
        "summary": ticket.get("title") or "",
        "description": description,
        "status": _status_label(ticket.get("status")),
        "classification": ticket.get("classification") or "",
        "verdict": resolved_verdict,
        "close_note": ticket.get("close_note") or "",
        "risk_score": extracted_risk_score,
    }


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True, "service": "soc_case_ui"})


@app.get("/{path_name:path}", include_in_schema=False)
def spa_catchall(path_name: str):
    # Preserve API/static behavior and only fallback to SPA for app routes.
    if path_name.startswith("api/") or path_name.startswith("static/") or path_name.startswith("assets/"):
        raise HTTPException(status_code=404, detail="Not found")

    index_path = _frontend_index()
    if index_path:
        return FileResponse(
            index_path,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    raise HTTPException(status_code=404, detail="Not found")
