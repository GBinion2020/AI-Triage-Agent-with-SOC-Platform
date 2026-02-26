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

if [[ ! -f ".env" ]]; then
  echo "Missing .env file at ${REPO_ROOT}/.env"
  echo "Copy .env.example to .env and set FEEDBACK_API_KEY first."
  exit 1
fi

feedback_api_key="$(read_env_value "FEEDBACK_API_KEY")"
if [[ -z "${feedback_api_key}" && -z "${FEEDBACK_API_KEY:-}" ]]; then
  echo "FEEDBACK_API_KEY is not set in .env or shell environment."
  exit 1
fi

if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

if ! python - <<'PY'
import importlib
import sys
required = ("fastapi", "uvicorn", "pydantic")
for mod in required:
    try:
        importlib.import_module(mod)
    except ModuleNotFoundError:
        sys.exit(1)
sys.exit(0)
PY
then
  echo "Missing webhook dependencies."
  echo "Run: source .venv/bin/activate && python -m pip install -r jira_webhook_local/requirements-webhook.txt"
  exit 1
fi

host="${FEEDBACK_RECEIVER_HOST:-$(read_env_value FEEDBACK_RECEIVER_HOST)}"
port="${FEEDBACK_RECEIVER_PORT:-$(read_env_value FEEDBACK_RECEIVER_PORT)}"
host="${host:-0.0.0.0}"
port="${port:-8001}"

echo "Starting Jira webhook API on ${host}:${port}"
python -m uvicorn feedback_api.app:app --host "${host}" --port "${port}"
