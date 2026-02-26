#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

source .venv/bin/activate

HOST="${SOC_UI_HOST:-0.0.0.0}"
PORT="${SOC_UI_PORT:-8088}"

uvicorn soc_case_ui.app:app --host "$HOST" --port "$PORT"
