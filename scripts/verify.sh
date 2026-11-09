#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

printf '\n== Python analysis tests ==\n'
cd "$ROOT/ai-service"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -v

printf '\n== Java API verification ==\n'
cd "$ROOT/backend"
if [[ -x /usr/libexec/java_home ]] && /usr/libexec/java_home -v 25 >/dev/null 2>&1; then
  export JAVA_HOME="$(/usr/libexec/java_home -v 25)"
  export PATH="$JAVA_HOME/bin:$PATH"
fi
mvn --batch-mode clean verify

printf '\n== Frontend tests and production build ==\n'
cd "$ROOT/frontend"
npm install --no-audit --no-fund
npm test
npm run build

printf '\nAll local verification steps completed.\n'
