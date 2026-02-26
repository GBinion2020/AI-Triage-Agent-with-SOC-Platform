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

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared is not installed."
  echo "Install on macOS: brew install cloudflared"
  exit 1
fi

if [[ ! -f ".env" ]]; then
  echo "Missing .env file at ${REPO_ROOT}/.env"
  exit 1
fi

tunnel_id="${CF_TUNNEL_ID:-$(read_env_value CF_TUNNEL_ID)}"
credentials_file="${CF_TUNNEL_CREDENTIALS_FILE:-$(read_env_value CF_TUNNEL_CREDENTIALS_FILE)}"
hostname="${CF_TUNNEL_HOSTNAME:-$(read_env_value CF_TUNNEL_HOSTNAME)}"
port="${FEEDBACK_RECEIVER_PORT:-$(read_env_value FEEDBACK_RECEIVER_PORT)}"

hostname="${hostname:-your-webhook-domain.example}"
port="${port:-8001}"

if [[ -z "${tunnel_id}" ]]; then
  echo "CF_TUNNEL_ID is empty. Run ./jira_webhook_local/setup_named_tunnel.sh first."
  exit 1
fi

if [[ -z "${credentials_file}" ]]; then
  echo "CF_TUNNEL_CREDENTIALS_FILE is empty. Run ./jira_webhook_local/setup_named_tunnel.sh first."
  exit 1
fi

if [[ ! -f "${credentials_file}" ]]; then
  echo "Tunnel credentials file not found: ${credentials_file}"
  exit 1
fi

cfg_dir="${REPO_ROOT}/jira_webhook_local/.generated"
mkdir -p "${cfg_dir}"
cfg_file="${cfg_dir}/cloudflared_config.yml"

python3 - <<'PY' "${REPO_ROOT}/jira_webhook_local/cloudflared_config.yml.tmpl" "${cfg_file}" "${tunnel_id}" "${credentials_file}" "${hostname}" "${port}"
from pathlib import Path
import sys

template_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
tunnel_id = sys.argv[3]
credentials_file = sys.argv[4]
hostname = sys.argv[5]
port = sys.argv[6]

text = template_path.read_text(encoding="utf-8")
text = text.replace("${CF_TUNNEL_ID}", tunnel_id)
text = text.replace("${CF_TUNNEL_CREDENTIALS_FILE}", credentials_file)
text = text.replace("${CF_TUNNEL_HOSTNAME}", hostname)
text = text.replace("${FEEDBACK_RECEIVER_PORT}", port)
out_path.write_text(text, encoding="utf-8")
PY

echo "Starting named tunnel for https://${hostname} -> http://127.0.0.1:${port}"
cloudflared tunnel --config "${cfg_file}" run "${tunnel_id}"
