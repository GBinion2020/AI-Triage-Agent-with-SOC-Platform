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

default_base_url="${FEEDBACK_PUBLIC_BASE_URL:-$(read_env_value FEEDBACK_PUBLIC_BASE_URL)}"
default_base_url="${default_base_url:-http://127.0.0.1:8001}"
base_url="${1:-${default_base_url}}"
payload_file="${2:-${SCRIPT_DIR}/sample_jira_payload.json}"
api_key="${X_API_KEY:-${FEEDBACK_API_KEY:-$(read_env_value FEEDBACK_API_KEY)}}"

if [[ -z "${api_key}" ]]; then
  echo "Missing API key. Set FEEDBACK_API_KEY in .env or export X_API_KEY."
  exit 1
fi

if [[ ! -f "${payload_file}" ]]; then
  echo "Payload file not found: ${payload_file}"
  exit 1
fi

url="${base_url%/}/webhook/jira?debug=true"
echo "Posting sample payload to ${url}"
curl -sS -X POST "${url}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${api_key}" \
  --data-binary "@${payload_file}"
echo
