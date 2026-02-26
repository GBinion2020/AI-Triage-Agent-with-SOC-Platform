# Pipeline Loop Walkthrough (Orchestrated v2)

## Main Investigation Lifecycle

1. Alert ingest + normalization
- Pull from Elastic.
- Build `NormalizedSecurityAlert` with deterministic analysis signals.

2. Pre-classifier + intake gate
- Reject malformed/empty alerts.
- `IntakeAgent` decides `close_benign` vs `investigate`.

3. Wave 1 plan and execution
- `SOCAnalystOrchestrator` generates strict JSON action plan.
- `ToolRunner` executes selected specialists in parallel.
- Each action emits structured output + artifact JSON.

4. Confidence evaluation
- Deterministic confidence meter scores wave results.
- If confidence target not met and budget remains, run wave 2.

5. Wave 2 pivots
- Orchestrator plans targeted follow-up actions from wave 1 evidence.
- Parallel execution and artifact capture repeated.

6. Final decision
- `SOC2DecisionAgent` consumes evidence summary + artifact refs + deterministic scoring.
- Emits final close note, action, and analyst journal.

7. Reporting and audit
- Email notification sent (Resend).
- Agent I/O JSONL and run artifacts retained for replay/audit.

## Jira Feedback Lifecycle

1. Jira automation posts to `/webhook/jira`.
2. `feedback_api/app.py` normalizes payload and validates API key.
3. `feedback_api/db.py` stores normalized feedback in SQLite/Postgres.
4. `context/feedback_rag.py` retrieves similar historical close notes on future alerts.
5. Intake/orchestration runs with that feedback context embedded.
