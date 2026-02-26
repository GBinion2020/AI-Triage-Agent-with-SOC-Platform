# Jira Webhook Local Runtime

This folder contains scripts for running and validating Jira webhook ingestion locally.

## What It Runs

- FastAPI endpoint: `POST /webhook/jira`
- API implementation: `feedback_api/app.py`
- Persistence layer: `feedback_api/db.py`
- Default database: `feedback_api/feedback.db` (SQLite)

## 1) Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r jira_webhook_local/requirements-webhook.txt
```

## 2) Configure `.env`

Create `.env` from `.env.example` and set at minimum:

```env
FEEDBACK_API_KEY="replace-with-long-random-secret"
FEEDBACK_RECEIVER_HOST=0.0.0.0
FEEDBACK_RECEIVER_PORT=8080
FEEDBACK_DB_PATH=feedback_api/feedback.db

# Jira custom field IDs in your tenant
JIRA_CLOSE_NOTE_FIELD=customfield_10101
JIRA_DETECTION_CLASSIFICATION_FIELD=customfield_10100
JIRA_TRIAGE_VERDICT_FIELD=customfield_10099
```

## 3) Start Webhook API

```bash
./jira_webhook_local/start_webhook_local.sh
```

## 4) Local Test

In a second terminal:

```bash
./jira_webhook_local/send_test_payload.sh
./jira_webhook_local/check_feedback_db.sh
```

If rows appear in feedback DB output, ingestion is working.

## 5) Jira Automation Target

For a temporary/public endpoint, point Jira automation to:

- URL: `https://<your-domain>/webhook/jira`
- Method: `POST`
- Headers:
  - `Content-Type: application/json`
  - `X-API-Key: <same FEEDBACK_API_KEY in .env>`
- Body template: `jira_webhook_local/jira_automation_payload_template.json`

## 6) Optional Named Tunnel Workflow

Set up a fixed hostname tunnel:

```bash
./jira_webhook_local/setup_named_tunnel.sh
./jira_webhook_local/run_named_tunnel.sh
```

Health check example:

```bash
./jira_webhook_local/check_webhook_endpoint.sh https://your-webhook-domain.example
```

Notes:

- Keep webhook API and tunnel process running at the same time.
- Generated runtime config is written under `jira_webhook_local/.generated/`.
