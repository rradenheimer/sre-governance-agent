#!/usr/bin/env bash
# Promote a release to the next rollout ring only after the preceding ring is healthy.
#
#   ./scripts/promote.sh --ring <ring> --version <vX.Y.Z> [--dry-run]
#
# Re-verifies the ring that precedes <ring> in config/rollout-rings.yaml with
# scripts/verify_rollout.py and, only if it meets the health threshold, deploys
# <ring> with scripts/deploy.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${PYTHON:-python3}"
CONFIG="${ROLLOUT_CONFIG:-$ROOT/config/rollout-rings.yaml}"
STATE="${ROLLOUT_STATE:-rollout-state/rollout-state.jsonl}"
RING=""
VERSION=""
DRY_ARGS=()

usage() {
  echo "usage: $0 --ring <ring> --version <vX.Y.Z> [--dry-run] [--config FILE] [--state FILE]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ring|--version|--config|--state)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --ring) RING="$2" ;;
        --version) VERSION="$2" ;;
        --config) CONFIG="$2" ;;
        --state) STATE="$2" ;;
      esac
      shift 2 ;;
    --dry-run) DRY_ARGS=(--dry-run); shift ;;
    *) usage ;;
  esac
done
if [ -z "$RING" ] || [ -z "$VERSION" ]; then usage; fi

PREVIOUS="$("$PYTHON" "$SCRIPT_DIR/verify_rollout.py" --config "$CONFIG" --ring "$RING" --previous-ring)"
echo "Verifying ring '$PREVIOUS' before promoting $VERSION to '$RING'"
"$PYTHON" "$SCRIPT_DIR/verify_rollout.py" --config "$CONFIG" --state "$STATE" \
  --ring "$PREVIOUS" "${DRY_ARGS[@]}"
"$SCRIPT_DIR/deploy.sh" --strategy canary --ring "$RING" --version "$VERSION" \
  --config "$CONFIG" --state "$STATE" "${DRY_ARGS[@]}"
