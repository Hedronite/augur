#!/usr/bin/env bash
# Generic scrub for the public repo: no IP addresses, tailnet names or home paths.
# Real host names can't be listed here (the list would leak them). To add a private
# denylist, point AUGUR_SCRUB_EXTRA at a file of extended regexes, one per line.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patterns=(
  '([0-9]{1,3}\.){3}[0-9]{1,3}'   # IPv4 (127.0.0.1 and 0.0.0.0 are allowed below)
  '\.ts\.net'                      # tailnet names
  '/Users/[A-Za-z]'                # macOS home paths
  '/home/[a-z]'                    # Linux home paths
)
allow='(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0)([^0-9.]|$)'

if [ -n "${AUGUR_SCRUB_EXTRA:-}" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && patterns+=("$line")
  done < "$AUGUR_SCRUB_EXTRA"
fi

fail=0
while IFS= read -r -d '' f; do
  case "$f" in LICENSE-*|go.sum|scripts/scrub.sh) continue ;; esac
  [ -f "$f" ] || continue
  for p in "${patterns[@]}"; do
    hits=$(grep -nE -- "$p" "$f" 2>/dev/null | grep -vE -- "$allow" || true)
    if [ -n "$hits" ]; then
      printf 'scrub: %s matches /%s/\n%s\n' "$f" "$p" "$hits" >&2
      fail=1
    fi
  done
done < <(git ls-files -co --exclude-standard -z)

[ "$fail" -eq 0 ] && echo "scrub: clean"
exit "$fail"
