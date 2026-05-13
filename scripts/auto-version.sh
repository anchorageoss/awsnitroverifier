#!/usr/bin/env bash
set -euo pipefail

# Computes a semver-shaped version that stacks on top of the highest existing
# v<MAJOR>.<MINOR>.<PATCH> git tag, so manually-cut baselines (e.g. v0.1.0) are
# respected and the version never regresses below them.
#
# Output format:
#   main/master:     <MAJOR>.<MINOR_BASE + commits_since_tag>.0+<branch>-<hash>
#   feature branch:  <MAJOR>.<MINOR_BASE + commits_tag_to_mergebase>.<commits_since_mergebase>+<branch>-<hash>
#
# Where MAJOR / MINOR_BASE come from the highest semver tag. If no semver tag
# exists, we fall back to MAJOR=0, MINOR_BASE=0 and use raw commit height.

# Resolve the raw branch name (before sanitization) so that comparisons against
# "main"/"master" can't be fooled by branches like `main.` or `main_` that
# collapse to `main-` after character sanitization.
#
# Precedence:
#   1. GITHUB_HEAD_REF — set on pull_request events; contains the PR source
#      branch (GITHUB_REF_NAME would be "<N>/merge" here, which is useless).
#   2. GITHUB_REF_NAME — set on push/workflow_dispatch events; the branch name.
#   3. git symbolic-ref --short HEAD — local developer runs.
RAW_BRANCH="${GITHUB_HEAD_REF:-}"
if [ -z "$RAW_BRANCH" ]; then
  RAW_BRANCH="${GITHUB_REF_NAME:-}"
fi
if [ -z "$RAW_BRANCH" ]; then
  if git symbolic-ref --short HEAD > /dev/null 2>&1; then
    RAW_BRANCH="$(git symbolic-ref --short HEAD)"
  fi
fi

SHORT_HASH=$(git rev-parse --short=12 HEAD)

# Sanitized branch for use in semver build metadata (allowed: [0-9A-Za-z-]).
# The trailing "-" is a separator before SHORT_HASH; omitted when branch is empty.
if [ -n "$RAW_BRANCH" ]; then
  # shellcheck disable=SC2001
  BRANCH_META="$(echo "$RAW_BRANCH" | sed 's/[^a-zA-Z0-9-]/-/g')-"
else
  BRANCH_META=
fi

# Find the highest existing semver tag (vMAJOR.MINOR.PATCH). Sort -V respects
# numeric ordering so v0.10.0 sorts above v0.2.0.
LATEST_TAG=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1 || true)

if [ -n "$LATEST_TAG" ]; then
  TAG_SEMVER="${LATEST_TAG#v}"
  MAJOR="${TAG_SEMVER%%.*}"
  REST="${TAG_SEMVER#*.}"
  MINOR_BASE="${REST%%.*}"
  # PATCH is intentionally ignored — distance from the tag goes into the MINOR
  # slot so each new commit on main bumps the minor (matches "v0.+distance").
else
  LATEST_TAG=""
  MAJOR=0
  MINOR_BASE=0
fi

# Count commits since the latest tag (or from root if no tag exists).
count_since_tag() {
  local target="$1"
  if [ -n "$LATEST_TAG" ]; then
    git rev-list --count "${LATEST_TAG}..${target}"
  else
    git rev-list --count "$target"
  fi
}

if [ "$RAW_BRANCH" = "main" ] || [ "$RAW_BRANCH" = "master" ]; then
  COMMITS_SINCE_TAG=$(count_since_tag HEAD)
  MINOR=$((MINOR_BASE + COMMITS_SINCE_TAG))
  echo "$MAJOR.$MINOR.0+${BRANCH_META}$SHORT_HASH"
  exit 0
fi

# Which main do we diff against?
REMOTE=$(git remote -v | awk '/[[:space:]]\(fetch\)/ && /anchorageoss\/awsnitroverifier/ {print $1; exit}')
if [ -z "$REMOTE" ]; then
  REMOTE="origin"
fi

# Try main first, fall back to master
DEFAULT_BRANCH="main"
if ! git rev-parse --verify "$REMOTE/$DEFAULT_BRANCH" > /dev/null 2>&1; then
  DEFAULT_BRANCH="master"
fi

MERGE_BASE=$(git merge-base "$REMOTE/$DEFAULT_BRANCH" HEAD)
if [ "$MERGE_BASE" = "$(git rev-parse "$REMOTE/$DEFAULT_BRANCH")" ]; then
  # Local remote-tracking ref may be stale — fetch to get the real merge base
  echo "Fetching $REMOTE..." >&2
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    git fetch "$REMOTE" >&2
  else
    git fetch "$REMOTE" > /dev/null 2>&1 || echo "Warning: fetch from $REMOTE failed, continuing with local ref" >&2
  fi
  MERGE_BASE=$(git merge-base "$REMOTE/$DEFAULT_BRANCH" HEAD)
fi

COMMITS_TAG_TO_MERGE_BASE=$(count_since_tag "$MERGE_BASE")
MINOR=$((MINOR_BASE + COMMITS_TAG_TO_MERGE_BASE))
COMMITS_SINCE_MERGE_BASE=$(git rev-list --count "${MERGE_BASE}..HEAD")
echo "$MAJOR.$MINOR.$COMMITS_SINCE_MERGE_BASE+${BRANCH_META}$SHORT_HASH"
