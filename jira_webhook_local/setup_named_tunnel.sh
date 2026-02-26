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

upsert_env_value() {
  local key="$1"
  local value="$2"
  local env_file="${REPO_ROOT}/.env"
  local escaped
  escaped="$(printf '%s' "${value}" | sed -e 's/[\/&]/\\&/g')"
  if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "${env_file}"; then
    sed -i '' -E "s|^[[:space:]]*(export[[:space:]]+)?${key}=.*$|${key}=\"${escaped}\"|" "${env_file}"
  else
    printf '%s="%s"\n' "${key}" "${value}" >> "${env_file}"
  fi
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

tunnel_name="${CF_TUNNEL_NAME:-$(read_env_value CF_TUNNEL_NAME)}"
tunnel_name="${tunnel_name:-soc-feedback-webhook}"

hostname="${CF_TUNNEL_HOSTNAME:-$(read_env_value CF_TUNNEL_HOSTNAME)}"
hostname="${hostname:-your-webhook-domain.example}"

port="${FEEDBACK_RECEIVER_PORT:-$(read_env_value FEEDBACK_RECEIVER_PORT)}"
port="${port:-8001}"

echo "Step 1/4: Authenticate cloudflared with Cloudflare account"
if [[ -f "${HOME}/.cloudflared/cert.pem" ]]; then
  echo "Existing Cloudflare cert found at ${HOME}/.cloudflared/cert.pem. Skipping login."
else
  echo "A browser window may open."
  cloudflared tunnel login
fi

echo "Step 2/4: Create named tunnel '${tunnel_name}' if missing"
create_status=0
create_output="$(cloudflared tunnel create "${tunnel_name}" 2>&1)" || create_status=$?

if [[ ${create_status} -ne 0 ]] && ! printf '%s' "${create_output}" | grep -q "already exists"; then
  printf '%s\n' "${create_output}"
  exit 1
fi

if printf '%s' "${create_output}" | grep -q "already exists"; then
  echo "Tunnel already exists. Using existing tunnel."
else
  printf '%s\n' "${create_output}"
fi

echo "Step 3/4: Resolve tunnel ID and credentials file"
list_output="$(cloudflared tunnel list 2>&1)" || {
  printf '%s\n' "${list_output}"
  exit 1
}
tunnel_id="$(printf '%s\n' "${list_output}" | awk -v name="${tunnel_name}" '$0 ~ name {print $1; exit}')"
if [[ -z "${tunnel_id}" ]]; then
  echo "Could not resolve tunnel ID for '${tunnel_name}'."
  echo "Run: cloudflared tunnel list"
  exit 1
fi

credentials_file="${HOME}/.cloudflared/${tunnel_id}.json"
if [[ ! -f "${credentials_file}" ]]; then
  echo "Tunnel credentials file not found: ${credentials_file}"
  exit 1
fi

echo "Step 4/4: Create DNS route ${hostname} -> tunnel ${tunnel_id}"
cloudflared tunnel route dns --overwrite-dns "${tunnel_name}" "${hostname}"

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

upsert_env_value "CF_TUNNEL_NAME" "${tunnel_name}"
upsert_env_value "CF_TUNNEL_ID" "${tunnel_id}"
upsert_env_value "CF_TUNNEL_CREDENTIALS_FILE" "${credentials_file}"
upsert_env_value "CF_TUNNEL_HOSTNAME" "${hostname}"
upsert_env_value "FEEDBACK_PUBLIC_BASE_URL" "https://${hostname}"

cat <<EOF
Named tunnel configured.
Generated config: ${cfg_file}

Updated .env with:
CF_TUNNEL_NAME="${tunnel_name}"
CF_TUNNEL_ID="${tunnel_id}"
CF_TUNNEL_CREDENTIALS_FILE="${credentials_file}"
CF_TUNNEL_HOSTNAME="${hostname}"
FEEDBACK_PUBLIC_BASE_URL="https://${hostname}"

Run tunnel with:
./jira_webhook_local/run_named_tunnel.sh
EOF
