#!/usr/bin/env bash
# Print the CHANGELOG.md section for VERSION (the text under "## [X.Y.Z]", up
# to the next heading or the link references). Fails if the section is missing
# or empty, so a release cannot go out without notes.
# Usage: scripts/release-notes.sh VERSION    (for example v0.1.0)
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: scripts/release-notes.sh VERSION" >&2
  exit 2
fi
ver="${1#v}"
cd "$(dirname "$0")/.."

body="$(awk -v ver="$ver" '
  /^## \[/ { if (on) exit; if (index($0, "## [" ver "]") == 1) { on = 1; next } }
  on && /^\[[^]]+\]: / { exit }
  on { print }
' CHANGELOG.md)"

if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "release-notes: CHANGELOG.md has no non-empty section '## [$ver]'" >&2
  exit 1
fi
printf '%s\n' "$body"
