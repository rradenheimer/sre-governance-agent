#!/usr/bin/env bash
# Roll back every repository touched in a failed rollout ring.
#
#   ./scripts/rollback.sh [--ring <ring>] [--state FILE] [--dry-run]
#
# Reads the rollout state written by scripts/deploy.sh. Without --ring it rolls
# back the most recently started ring. For each repository the ring touched:
#   * open rollout PR    -> closed and its branch deleted; the default branch
#                           still runs the recorded previous version;
#   * merged rollout PR  -> a rollback PR restores the recorded previous
#                           workflow blob (or removes files the rollout added);
#   * no PR              -> the partially written rollout branch is deleted.
# Repositories that were already on the target version are never modified.
set -euo pipefail

STATE="${ROLLOUT_STATE:-rollout-state/rollout-state.jsonl}"
DRY_RUN="${ROLLOUT_DRY_RUN:-false}"
RING=""
WORKFLOW_FILE=".github/workflows/sre-governance.yml"
PROFILE_FILE=".sre/profile"

usage() { echo "usage: $0 [--ring <ring>] [--state FILE] [--dry-run]" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ring|--state)
      [ "$#" -ge 2 ] || usage
      if [ "$1" = "--ring" ]; then RING="$2"; else STATE="$2"; fi
      shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) usage ;;
  esac
done

if [ ! -s "$STATE" ]; then
  echo "No rollout state at $STATE; nothing was deployed, nothing to roll back."
  exit 0
fi
jq -s . "$STATE" > /dev/null || { echo "::error::rollout state $STATE is malformed" >&2; exit 1; }
if [ -z "$RING" ]; then
  # The most recently started ring is the one that failed.
  RING="$(jq -rs 'map(select(.ring)) | last | .ring // empty' "$STATE")"
  if [ -z "$RING" ]; then
    echo "No ring was deployed; nothing to roll back."
    exit 0
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

blob_sha() {  # repo path ref -> blob sha, empty on 404
  if gh api "repos/$1/contents/$2?ref=$3" --jq .sha 2>"$WORK/err"; then
    return 0
  fi
  grep -q "HTTP 404" "$WORK/err" || { cat "$WORK/err" >&2; return 1; }
}

restore_merged() {  # repo version previous_version previous_blob created_profile default_branch
  local repo="$1" version="$2" previous="$3" blob="$4" created="$5" base="$6"
  local branch="sre-governance/rollback-$version" message="revert(sre-governance): roll back $version to $previous"
  local base_sha current content url
  base_sha="$(gh api "repos/$repo/git/ref/heads/$base" --jq .object.sha)"
  if gh api "repos/$repo/git/ref/heads/$branch" > /dev/null 2>&1; then
    gh api -X PATCH "repos/$repo/git/refs/heads/$branch" -f sha="$base_sha" -F force=true > /dev/null
  else
    gh api -X POST "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$base_sha" > /dev/null
  fi
  current="$(blob_sha "$repo" "$WORKFLOW_FILE" "$branch")"
  if [ "$blob" != "none" ]; then
    content="$(gh api "repos/$repo/git/blobs/$blob" --jq '.content | gsub("\n"; "")')"
    local args=(-X PUT "repos/$repo/contents/$WORKFLOW_FILE" -f branch="$branch"
      -f message="$message" -f content="$content")
    [ -z "$current" ] || args+=(-f sha="$current")
    gh api "${args[@]}" > /dev/null
  elif [ -n "$current" ]; then
    gh api -X DELETE "repos/$repo/contents/$WORKFLOW_FILE" -f branch="$branch" \
      -f message="$message" -f sha="$current" > /dev/null
  fi
  if [ "$created" = "true" ]; then
    current="$(blob_sha "$repo" "$PROFILE_FILE" "$branch")"
    if [ -n "$current" ]; then
      gh api -X DELETE "repos/$repo/contents/$PROFILE_FILE" -f branch="$branch" \
        -f message="$message" -f sha="$current" > /dev/null
    fi
  fi
  url="$(gh pr list -R "$repo" --head "$branch" --state open --json url --jq '.[0].url // empty')"
  if [ -z "$url" ]; then
    url="$(gh pr create -R "$repo" --base "$base" --head "$branch" --title "$message" \
      --body "Automated rollback: the $version rollout breached its health threshold.")"
  fi
  echo "$repo: rollback PR to $previous: $url"
}

rollback_repo() {  # repo version previous_version previous_blob created_profile default_branch branch
  local repo="$1" version="$2" previous="$3" branch="$7" pr state url
  pr="$(gh pr list -R "$repo" --head "$branch" --state all --json state,url \
    --jq '.[0] // empty | [.state, .url] | @tsv')"
  state="${pr%%$'\t'*}"
  url="${pr#*$'\t'}"
  case "$state" in
    OPEN)
      gh pr close "$url" -R "$repo" --delete-branch \
        --comment "Automated rollback: the $version rollout breached its health threshold; $previous remains in effect."
      echo "$repo: closed $url; $previous remains in effect" ;;
    MERGED)
      restore_merged "$@" ;;
    *)
      if gh api "repos/$repo/git/ref/heads/$branch" > /dev/null 2>&1; then
        gh api -X DELETE "repos/$repo/git/refs/heads/$branch" > /dev/null
      fi
      echo "$repo: no open rollout PR; $previous remains in effect" ;;
  esac
}

FAILED=0
while IFS=$'\t' read -r REPO VERSION PREVIOUS BLOB CREATED BASE BRANCH ENTRY_DRY_RUN; do
  if [ "$DRY_RUN" = "true" ]; then
    echo "DRY RUN: would roll back $REPO ($RING) from $VERSION to $PREVIOUS"
    continue
  fi
  if [ "$ENTRY_DRY_RUN" = "true" ]; then
    echo "$REPO: dry-run entry; no changes were made, nothing to roll back"
    continue
  fi
  # Run in a background subshell so `set -e` applies inside and one failing
  # repository does not prevent rolling back the others.
  ( rollback_repo "$REPO" "$VERSION" "$PREVIOUS" "$BLOB" "$CREATED" "$BASE" "$BRANCH" ) &
  if ! wait "$!"; then
    echo "::error::rollback failed for $REPO; restore $PREVIOUS manually" >&2
    FAILED=1
  fi
done < <(jq -rs --arg ring "$RING" '
  map(select(.ring == $ring and .phase == "touched")) | unique_by(.repo) | .[]
  | [.repo, .version, .previous_version, .previous_blob_sha, (.created_profile | tostring),
     .default_branch, .branch, (.dry_run | tostring)] | @tsv' "$STATE")

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
echo "Rollback of ring '$RING' complete."
