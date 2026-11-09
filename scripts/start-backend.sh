#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"

# Avoid starting a second Spring Boot process against the same H2 file database.
if command -v lsof >/dev/null 2>&1; then
  existing_pid="$(lsof -tiTCP:8080 -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${existing_pid}" ]]; then
    echo "ERROR: Port 8080 is already in use (PID: ${existing_pid})." >&2
    echo "Stop the existing TrustForge backend with Ctrl+C in its terminal before starting another." >&2
    echo "Do not delete backend/data/trustforge.mv.db; it contains your scan history." >&2
    exit 1
  fi
fi

if [[ -x /usr/libexec/java_home ]] && /usr/libexec/java_home -v 25 >/dev/null 2>&1; then
  export JAVA_HOME="$(/usr/libexec/java_home -v 25)"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

export ANALYSIS_SERVICE_URL="${ANALYSIS_SERVICE_URL:-http://127.0.0.1:8000}"
echo "TrustForge API -> http://localhost:8080"
echo "Analysis service -> ${ANALYSIS_SERVICE_URL}"
exec mvn spring-boot:run
