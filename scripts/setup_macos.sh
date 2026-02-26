#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PY_BIN="${PY_BIN:-python3}"
INSTALL_DEV="${INSTALL_DEV:-false}"

if [ ! -d ".venv" ]; then
  "$PY_BIN" -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip

if [ "$INSTALL_DEV" = "true" ]; then
  python -m pip install -r requirements-dev.txt
else
  python -m pip install -r requirements.txt
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

echo "Setup complete. Activate with: source .venv/bin/activate"
