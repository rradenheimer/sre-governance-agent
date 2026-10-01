#!/usr/bin/env bash
# Deploy a released SRE Governance version to every repository in one rollout ring.
#
#   ./scripts/deploy.sh --strategy canary --ring <ring> --version <vX.Y.Z> [--dry-run]
#
# For each repository listed for the ring in config/rollout-rings.yaml, this
# opens or updates a pull request on `sre-governance/rollout-<version>` that
# pins `.github/workflows/sre-governance.yml` to the release tag and scaffolds
# `.sre/profile` when missing. Default branches are never pushed to directly.
# The previous version of every touched repository is appended to the rollout
# state file (JSONL) so scripts/rollback.sh can restore it. Requires `gh`
# authenticated through GH_TOKEN; --dry-run performs read-only API calls.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${PYTHON:-python3}"
CONFIG="${ROLLOUT_CONFIG:-$ROOT/config/rollout-rings.yaml}"
STATE="${ROLLOUT_STATE:-rollout-state/rollout-state.jsonl}"
DRY_RUN="${ROLLOUT_DRY_RUN:-false}"
STRATEGY=""
RING=""
VERSION=""
TEMPLATE=""
ENGINE_REPO="rradenheimer/sre-governance-agent"
TEMPLATE_PATH="agents/copilot/.github/workflows/sre-governance.yml"
WORKFLOW_FILE=".github/workflows/sre-governance.yml"
PROFILE_FILE=".sre/profile"

usage() {
  echo "usage: $0 --strategy canary --ring <ring> --version <vX.Y.Z> [--dry-run]" \
    "[--config FILE] [--state FILE] [--template FILE]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --strategy|--ring|--version|--config|--state|--template)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --strategy) STRATEGY="$2" ;;
        --ring) RING="$2" ;;
        --version) VERSION="$2" ;;
        --config) CONFIG="$2" ;;
        --state) STATE="$2" ;;
        --template) TEMPLATE="$2" ;;
      esac
      shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) usage ;;
  esac
done

# Ring-by-ring canary promotion is the only supported strategy.
[ "$STRATEGY" = "canary" ] || { echo "::error::unsupported --strategy '$STRATEGY'" >&2; exit 2; }
[ -n "$RING" ] || usage
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "::error::--version must be a release tag like v1.2.3" >&2; exit 2; }
[ "$DRY_RUN" = "true" ] || [ "$DRY_RUN" = "false" ] || {
  echo "::error::ROLLOUT_DRY_RUN must be true or false" >&2; exit 2; }

REPO_LIST="$("$PYTHON" "$SCRIPT_DIR/verify_rollout.py" --config "$CONFIG" --ring "$RING" --list-repos)"
DEFAULT_PROFILE="$("$PYTHON" "$SCRIPT_DIR/verify_rollout.py" --config "$CONFIG" --ring "$RING" --default-profile)"
mapfile -t REPOS <<< "$REPO_LIST"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$TEMPLATE" ]; then
  # Deploy exactly what the signed release tag contains.
  TEMPLATE="$WORK/template.yml"
  git -C "$ROOT" show "refs/tags/$VERSION:$TEMPLATE_PATH" > "$TEMPLATE"
fi
RENDERED="$WORK/sre-governance.yml"
awk -v version="$VERSION" -v engine="$ENGINE_REPO" '
  $1 == "repository:" && $2 == engine { pinned = 1; print; next }
  pinned && $1 == "ref:" { sub(/ref:.*/, "ref: " version); pinned = 0; count++ }
  { print }
  END { if (count != 1) exit 1 }
' "$TEMPLATE" > "$RENDERED" || {
  echo "::error::template does not pin $ENGINE_REPO exactly once" >&2; exit 1; }

pinned_version() {
  awk -v engine="$ENGINE_REPO" '
    $1 == "repository:" && $2 == engine { pinned = 1; next }
    pinned && $1 == "ref:" { gsub(/["'\'']/, "", $2); print $2; exit }
  '
}

# Prints "<blob sha>\t<base64 content>" for an existing file, nothing on 404.
get_file() {
  local out
  if out="$(gh api "repos/$1/contents/$2?ref=$3" \
      --jq '[.sha, (.content | gsub("\n"; ""))] | @tsv' 2>"$WORK/err")"; then
    printf '%s\n' "$out"
  elif grep -q "HTTP 404" "$WORK/err"; then
    return 0
  else
    cat "$WORK/err" >&2
    return 1
  fi
}

record() {
  mkdir -p "$(dirname "$STATE")"
  jq -nc --arg phase "$1" --arg ring "$RING" --arg repo "$REPO" --arg version "$VERSION" \
    --arg previous_version "$PREV_VERSION" --arg previous_blob_sha "$PREV_BLOB" \
    --argjson created_profile "$CREATE_PROFILE" --arg default_branch "$DEFAULT_BRANCH" \
    --arg branch "$BRANCH" --arg head_sha "${2:-}" --arg pr_url "${3:-}" \
    --argjson dry_run "$DRY_RUN" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{ts: $ts, phase: $phase, ring: $ring, repo: $repo, version: $version,
      previous_version: $previous_version, previous_blob_sha: $previous_blob_sha,
      created_profile: $created_profile, default_branch: $default_branch,
      branch: $branch, head_sha: $head_sha, pr_url: $pr_url, dry_run: $dry_run}' >> "$STATE"
}

put_file() {  # repo path local_file branch [blob sha being replaced]
  local args=(-X PUT "repos/$1/contents/$2" -f branch="$4"
    -f message="chore(sre-governance): roll out $VERSION ($RING ring)"
    -f content="$(base64 -w0 < "$3")")
  [ -z "${5:-}" ] || args+=(-f sha="$5")
  gh api "${args[@]}" > /dev/null
}

BRANCH="sre-governance/rollout-$VERSION"
RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$ENGINE_REPO}/actions/runs/${GITHUB_RUN_ID:-local}"
printf '%s\n' "$DEFAULT_PROFILE" > "$WORK/profile"

# Mark the ring as in progress before any API call so rollback targets this ring
# even if the first repository fails before it is recorded.
mkdir -p "$(dirname "$STATE")"
jq -nc --arg ring "$RING" --arg version "$VERSION" --argjson dry_run "$DRY_RUN" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{ts: $ts, phase: "ring_started", ring: $ring, version: $version, dry_run: $dry_run}' >> "$STATE"

for REPO in "${REPOS[@]}"; do
  DEFAULT_BRANCH="$(gh api "repos/$REPO" --jq .default_branch)"
  BASE_SHA="$(gh api "repos/$REPO/git/ref/heads/$DEFAULT_BRANCH" --jq .object.sha)"
  CURRENT="$(get_file "$REPO" "$WORKFLOW_FILE" "$DEFAULT_BRANCH")"
  PREV_BLOB="none"
  PREV_VERSION="none"
  if [ -n "$CURRENT" ]; then
    PREV_BLOB="${CURRENT%%$'\t'*}"
    PREV_VERSION="$(printf '%s' "${CURRENT#*$'\t'}" | base64 -d | pinned_version)"
    PREV_VERSION="${PREV_VERSION:-unpinned}"
  fi
  PROFILE_CURRENT="$(get_file "$REPO" "$PROFILE_FILE" "$DEFAULT_BRANCH")"
  CREATE_PROFILE=true
  [ -z "$PROFILE_CURRENT" ] || CREATE_PROFILE=false

  if [ "$PREV_VERSION" = "$VERSION" ] && [ "$CREATE_PROFILE" = false ]; then
    echo "$REPO: already on $VERSION; nothing to deploy"
    record unchanged
    record deployed "$BASE_SHA"
    continue
  fi
  if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN: $REPO ($RING): $PREV_VERSION -> $VERSION on $BRANCH" \
      "(scaffold $PROFILE_FILE: $CREATE_PROFILE)"
    record touched
    continue
  fi

  # Record the previous version before mutating so rollback covers partial failures.
  record touched
  if gh api "repos/$REPO/git/ref/heads/$BRANCH" > /dev/null 2>&1; then
    gh api -X PATCH "repos/$REPO/git/refs/heads/$BRANCH" -f sha="$BASE_SHA" -F force=true > /dev/null
  else
    gh api -X POST "repos/$REPO/git/refs" -f ref="refs/heads/$BRANCH" -f sha="$BASE_SHA" > /dev/null
  fi
  put_file "$REPO" "$WORKFLOW_FILE" "$RENDERED" "$BRANCH" "${PREV_BLOB#none}"
  if [ "$CREATE_PROFILE" = true ]; then
    put_file "$REPO" "$PROFILE_FILE" "$WORK/profile" "$BRANCH"
  fi
  HEAD_SHA="$(gh api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)"
  PR_URL="$(gh pr list -R "$REPO" --head "$BRANCH" --state open --json url --jq '.[0].url // empty')"
  if [ -z "$PR_URL" ]; then
    PR_URL="$(gh pr create -R "$REPO" --base "$DEFAULT_BRANCH" --head "$BRANCH" \
      --title "chore(sre-governance): roll out $VERSION" \
      --body "Staged rollout of SRE Governance $VERSION (ring: $RING) from $RUN_URL. Previous version: $PREV_VERSION. Promotion requires the SRE Governance scan on this pull request to pass; on failure the rollout closes this pull request automatically.")"
  fi
  echo "$REPO ($RING): $PREV_VERSION -> $VERSION via $PR_URL"
  record deployed "$HEAD_SHA" "$PR_URL"
done
