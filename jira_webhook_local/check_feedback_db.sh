#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

read_env_value() {
  local key="$1"
  local env_file="${REPO_ROOT}/.env"
  if [[ ! -f "${env_file}" ]]; then
    return 0
  fi
  local line value
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "${env_file}" | tail -n1 || true)"
  value="${line#*=}"
  value="${value%%#*}"
  value="$(printf '%s' "${value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  echo "${value}"
}

db_path="${1:-${FEEDBACK_DB_PATH:-$(read_env_value FEEDBACK_DB_PATH)}}"
db_path="${db_path:-feedback_api/feedback.db}"

if [[ ! -f "${db_path}" ]]; then
  echo "Database file not found: ${db_path}"
  exit 1
fi

echo "Reading latest feedback rows from ${db_path}"
sqlite3 "${db_path}" \
  "SELECT id, issue_key, triage_verdict, detection_classification, substr(close_note,1,120), jira_updated_ms FROM jira_feedback ORDER BY id DESC LIMIT 10;"
