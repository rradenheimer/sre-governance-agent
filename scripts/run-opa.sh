#!/usr/bin/env bash
# Scan a repo then run the OPA/Rego policy gate locally.
# Usage: scripts/run-opa.sh [REPO_PATH] [PROFILE]
# Installs nothing; uses conftest/opa if present, else the Python fallback.
set -euo pipefail

REPO="${1:-.}"
PROFILE="${2:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"

if [ -z "$PROFILE" ]; then
  if [ -f "$REPO/.sre/profile" ]; then PROFILE="$(tr -d '[:space:]' < "$REPO/.sre/profile")"; else PROFILE="commercial"; fi
fi

OUT="${ROOT}/sre-reports"
echo ">> Scanning $REPO with profile '$PROFILE'"
python -m sre_governance.cli scan --repo "$REPO" --profile "$PROFILE" --format json --out "$OUT" --audit "$REPO/.sre/audit.jsonl"

# Optional: run native rego unit tests if opa is available.
if command -v opa >/dev/null 2>&1; then
  echo ">> opa test policies/opa"
  opa test "${ROOT}/policies/opa" -v || true
fi

echo ">> Running policy gate"
python "${ROOT}/scripts/opa_gate.py" --report "${OUT}/sre-governance-report.json" "${@:3}"
