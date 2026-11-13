#!/usr/bin/env bash
# Generic scrub for the public repo: no IP addresses, tailnet names or home paths.
# Real host names can't be listed here (the list would leak them). To add a private
# denylist, point AUGUR_SCRUB_EXTRA at a file of extended regexes, one per line.
set -euo pipefail

# Self-test: a loopback literal must not hide a real address on the same line.
if [ "${1:-}" = "--self-test" ]; then
  self="$(cd "$(dirname "$0")" && pwd)/scrub.sh"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$tmp" init -q
  printf 'listen on http://127.0.0.1:9093 or 0.0.0.0\n' > "$tmp/ok.txt"
  git -C "$tmp" add ok.txt
  (cd "$tmp" && bash "$self" >/dev/null 2>&1) || { echo "self-test: clean file was flagged" >&2; exit 1; }
  for bad in 'peer http://127.0.0.1:9093 and 10.20.30.40' 'host.example.ts.net 127.0.0.1' '/Users/someone 127.0.0.1'; do
    printf '%s\n' "$bad" > "$tmp/bad.txt"
    git -C "$tmp" add bad.txt
    if (cd "$tmp" && bash "$self" >/dev/null 2>&1); then echo "self-test: missed: $bad" >&2; exit 1; fi
  done
  echo "scrub self-test: ok"
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"

patterns=(
  '([0-9]{1,3}\.){3}[0-9]{1,3}'   # IPv4 (127.0.0.1 and 0.0.0.0 are allowed below)
  '\.ts\.net'                      # tailnet names
  '/Users/[A-Za-z]'                # macOS home paths
  '/home/[a-z]'                    # Linux home paths
)
# Loopback and wildcard literals are blanked out *before* matching, so a real
# address on the same line is still caught. Run twice: adjacent literals share a boundary.
blank() {
  sed -E 's/(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0)([^0-9.]|$)/\1_\3/g' | sed -E 's/(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0)([^0-9.]|$)/\1_\3/g'
}

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
    hits=$(blank < "$f" | grep -nE -- "$p" || true)
    if [ -n "$hits" ]; then
      printf 'scrub: %s matches /%s/\n%s\n' "$f" "$p" "$hits" >&2
      fail=1
    fi
  done
done < <(git ls-files -co --exclude-standard -z)

[ "$fail" -eq 0 ] && echo "scrub: clean"
exit "$fail"
