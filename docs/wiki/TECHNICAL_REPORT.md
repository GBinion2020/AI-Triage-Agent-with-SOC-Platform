# Technical Report (Orchestrated v2)

## 1. Scope

This report covers the production-oriented architecture now implemented in the repository:
- wave-based SOC orchestration
- strict tool contracts
- artifact-centric auditability
- deterministic scoring preserved through final decisioning

## 2. Core Design

### 2.1 Investigation Model

- Intake gates alert to `close_benign` or `investigate`.
- Investigation is run by `SOCAnalystOrchestrator` in max two waves.
- Each wave plans structured actions, then executes specialist tools in parallel.
- Results are merged into state and persisted as artifacts.
- Confidence meter decides whether to run wave 2.
- `SOC2DecisionAgent` outputs close note/action while respecting deterministic classification.

### 2.2 Deterministic Boundaries

- Max waves hard-capped at 2.
- Max actions per wave hard-capped.
- Parallelism hard-capped.
- SIEM baseline action required in wave 1.
- Duplicate actions suppressed via idempotency key.
- Existing policy engine still enforces tool constraints.

## 3. Data and Contract Surfaces

### 3.1 Orchestrator Contracts

Primary models in `/orchestrator/models.py`:
- `OrchestratorPlan`
- `OrchestratorAction`
- `ToolExecutionResult`
- `WaveExecutionReport`
- `OrchestratorRunReport`
- `ArtifactReference`

### 3.2 Tool Capability Cards

Cards in `/tool_registry/cards/*.json` define:
- tool identity and description
- JSON input/output schemas
- guardrails
- timeout/retry budgets
- cost class

### 3.3 Artifact Storage

`/orchestrator/artifacts.py` writes immutable evidence and metadata:
- `tool_results/<tool>/<action_id>.json`
- `meta/events.jsonl`
- run metadata JSON

## 4. Specialist Layer

Implemented specialists:
- SIEM (`siem_specialist.py`)
- IOC enrichment (`ioc_enrichment_specialist.py`)
- OSINT (`osint_specialist.py`)
- VirusTotal (`virustotal_specialist.py`)
- Timeline (`timeline_specialist.py`)
- Entra (`entra_specialist.py`)

Key safety improvements:
- internal IP suppression for VT/OSINT
- trusted-domain safe OSINT
- no state mutation side effects inside SIEM specialist action loop
- file/path/process strings no longer misclassified as domains in IOC enrichment

## 5. Final Decisioning

`SOC2DecisionAgent` receives:
- alert payload
- orchestration summary
- artifact references
- deterministic scoring payload

Output is strict JSON with:
- summary
- action
- MITRE techniques
- analyst journal

Classification and score remain deterministic and are not LLM-overridden.

## 6. Feedback Loop

Jira webhook ingestion is handled by:
- `/feedback_api/app.py`
- `/feedback_api/db.py`

Storage supports SQLite and Postgres. Updated timestamp normalization converts Jira `updated` values into sortable epoch milliseconds for robust dedupe/order behavior.

## 7. Validation Evidence

Validation performed in this workspace:
- static compile checks across updated modules
- unit/replay tests (`pytest`) passing
- multiple live end-to-end runs against real alert data with:
  - two-wave orchestration
  - artifact generation
  - exact agent I/O logs
  - final SOC2 decision output
  - outbound notification delivery

## 8. Operational Notes

- Use `PIPELINE_ARCH=orchestrated` for v2 architecture.
- Use `PIPELINE_ARCH=legacy` to fallback to legacy loop.
- Entra specialist requires credential env vars or it safely returns `skipped`.
- TLS verification for Elastic is env-controlled (`ELASTIC_VERIFY_TLS`, `ELASTIC_CA_BUNDLE`).

## 9. Elastic Setup References

Use these external references for Elastic-on-Docker setup:

- Docker repo: [evermight/elastic-stack-docker-part-two](https://github.com/evermight/elastic-stack-docker-part-two)
- Official article: [Getting started with the Elastic Stack and Docker Compose (Part 2)](https://www.elastic.co/blog/getting-started-with-the-elastic-stack-and-docker-compose-part-2)
- Video walkthrough: [Elastic setup walkthrough (YouTube)](https://www.youtube.com/watch?v=q74_FfM7sn0)
