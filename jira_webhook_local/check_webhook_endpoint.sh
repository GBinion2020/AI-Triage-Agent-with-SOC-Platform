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

base_url="${1:-${FEEDBACK_PUBLIC_BASE_URL:-$(read_env_value FEEDBACK_PUBLIC_BASE_URL)}}"
if [[ -z "${base_url}" ]]; then
  base_url="http://127.0.0.1:${FEEDBACK_RECEIVER_PORT:-$(read_env_value FEEDBACK_RECEIVER_PORT)}"
fi
base_url="${base_url%/}"

echo "Checking ${base_url}/health"
response="$(curl -sS -w '\n%{http_code}' "${base_url}/health")"
http_code="${response##*$'\n'}"
body="${response%$'\n'*}"

echo "HTTP ${http_code}"
if [[ -n "${body}" ]]; then
  echo "${body}"
fi

if [[ "${http_code}" != "200" ]]; then
  exit 1
fi
