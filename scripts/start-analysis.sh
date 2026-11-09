#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../ai-service"

# Avoid starting a duplicate Uvicorn process on the same local analysis port.
if command -v lsof >/dev/null 2>&1; then
  existing_pid="$(lsof -tiTCP:8000 -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${existing_pid}" ]]; then
    echo "ERROR: Port 8000 is already in use (PID: ${existing_pid})." >&2
    echo "Stop the existing analysis service with Ctrl+C before starting another." >&2
    exit 1
  fi
fi

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install -r requirements.txt
exec uvicorn app.main:app --host 127.0.0.1 --port 8000
