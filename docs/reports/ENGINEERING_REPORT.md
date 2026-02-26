# Engineering Report: Enterprise Agentic SOC (v1.04)

## 1) Executive Summary

This codebase implements a SOC triage pipeline that combines deterministic control logic with LLM-driven investigation planning. The primary production path is the orchestrated architecture (`PIPELINE_ARCH=orchestrated`), while a legacy loop remains available for rollback and compatibility.

Core outcomes:

- Intake and normalize Elastic alerts into a stable schema.
- Apply deterministic pre-classification and policy controls.
- Execute bounded specialist actions in parallel waves.
- Persist auditable artifacts for every agent/tool decision.
- Surface analyst workflow through a FastAPI/React SOC Case UI.
- Support external feedback ingestion through Jira webhook payloads.

## 2) Runtime Modes

### Orchestrated mode (default)

- Entry: `main.py` + `OrchestrationService`.
- Planning: `SOCAnalystOrchestrator.plan_wave(...)` produces strict JSON plans.
- Execution: `ToolRunner.run_wave(...)` executes specialist actions in bounded parallelism.
- Feedback gate: wave confidence scoring determines whether wave 2 is required.
- Final decision: `SOC2DecisionAgent` returns classification/action/close-note context.

### Legacy mode

- Entry: `main.py` with `PIPELINE_ARCH=legacy`.
- Loop-based planner/executor (`InvestigationAgent`, `ReasoningAgent`, `DeterministicPlanner`, `ToolExecutor`).
- Risk and confidence checkpoints terminate when investigation is conclusive.
- Final decision via `DecisionAgent`.

## 3) End-to-End Pipeline Behavior

1. Alert acquisition
- `AlertIngestor.fetch_latest_alerts(...)` queries Elastic (`.alerts-security.alerts-*`) and normalizes to `NormalizedSecurityAlert`.

2. Deterministic pre-classification
- `PreClassifier.classify(...)` performs static early filtering before LLM cost/latency is incurred.

3. Context creation
- `build_initial_state(...)` initializes `InvestigationState` and attempts to pull related historical lessons from feedback storage.

4. Intake decision
- `IntakeAgent.evaluate(...)` decides whether to close benign or proceed.

5. Investigation execution
- Orchestrated or legacy path executes evidence collection and IOC enrichment under policy constraints.

6. Scoring and decision
- Deterministic score/risk factors are recomputed prior to final decision output.
- Output includes classification, score, recommended action, and analyst-facing summary.

7. Artifacting and notifications
- Pipeline logger writes structured agent/tool traces.
- Run metadata and tool result payloads are persisted to `runs/`.
- Optional email notifications are sent if Resend credentials are configured.

## 4) Major Components

## Ingestion and Normalization

- `intake/ingest.py`: Elastic query and ECS-style normalization.
- `intake/logic.py`: deterministic signal derivation.
- `schemas/alert.py`: canonical normalized alert schema.

## Control and Policy Layer

- `control/policy_engine.py`: tool permission checks.
- `control/planner.py`: deterministic fallback planning logic.
- `orchestrator/policy.py`: hard bounds for waves/actions/parallelism.

## Agent Layer

- `agents/intake_agent.py`: initial disposition decision.
- `agents/investigation_agent.py` + `agents/reasoning_agent.py`: legacy loop analysis.
- `agents/soc2_decision_agent.py`: orchestrated final output.

## Orchestrator Layer

- `orchestrator/soc_analyst_agent.py`: wave plan generation prompt + strict JSON parsing.
- `orchestrator/runner.py`: bounded parallel execution, retry/backoff, timeout enforcement, idempotency.
- `orchestrator/artifacts.py`: structured run and result storage.
- `orchestrator/confidence.py`: wave continuation logic.

## Tooling and Specialists

- Specialist implementations in `orchestrator/specialists/`.
- Tool contracts in `tool_registry/cards/*.json` define request schema, guardrails, and execution limits.

## Web and Feedback Surfaces

- `soc_case_ui/app.py`: FastAPI backend for SOC dashboard/cases/audit views and pipeline session management.
- `soc_case_ui/frontend/`: React SPA assets and source.
- `feedback_api/app.py`: Jira webhook endpoint with API key validation and payload normalization.
- `feedback_api/db.py`: SQLite/PostgreSQL write path for normalized feedback.

## 5) Data Stores and Artifact Layout

- Ticket DB: `soc_case_ui/soc_ui.db` (SQLite, created on demand).
- Feedback DB: `feedback_api/feedback.db` by default (or PostgreSQL via `FEEDBACK_DB_URL`).
- Orchestrator artifacts: `runs/<alert_id>/<run_id>/...`
- Agent I/O logs: `pipeline_logs/agent_io_*.jsonl`
- Analyst case bundles: `cases/<ticket_key>_<timestamp>_<alert_id>/...`

## 6) Operational Guardrails

- Parallelism and action counts are hard-capped by environment-driven policy.
- Specialist calls are retried with exponential backoff and timeout budgets.
- Duplicate action execution in the same run is blocked by idempotency keys.
- IOC and OSINT processing is constrained to reduce risky or noisy enrichment.

## 7) Configuration Surface

Primary runtime controls are in `.env` and templated in `.env.example`.

Critical categories:

- Elastic connectivity and TLS behavior.
- LLM provider/model and timeouts.
- Orchestration control bounds.
- SOC UI paths/ports and Jira sync toggles.
- Feedback API auth and persistence mode.
- OSINT/Entra optional integrations.

## 8) Reliability and Failure Modes

Expected controlled failures:

- Elastic unavailable: alert fetch errors return non-zero exit and no ticket creation.
- Missing external LLM credentials: startup validation failure in `LLMClient`.
- Tool/specialist errors: recorded in run artifacts and agent I/O logs, with retry attempts.
- No alerts processed: pipeline ends cleanly with no case creation.

## 9) Test and Verification Coverage

The repository includes pytest suites for:

- Artifact storage and orchestration behavior.
- Tool registry and specialist logic.
- Feedback database behavior.
- SOC Case UI API behavior and ticket workflow.

Command:

```bash
source .venv/bin/activate
pytest -q
```

## 10) Recommendations for Public Repository Hardening

1. Keep runtime/generated artifacts ignored (`.env`, `.cache`, DB files, `cases/`, `runs/`, `pipeline_logs/`, generated tunnel config).
2. Use secret scanning in CI (e.g., `gitleaks` or GitHub Advanced Security).
3. Add a minimal CI workflow for lint + tests + dependency audit.
4. Publish an explicit threat model and supported deployment profiles (local lab vs production).
