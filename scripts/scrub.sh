#!/usr/bin/env bash
# Generic scrub for the public repo: no IP addresses, tailnet names or home paths.
# Real host names can't be listed here (the list would leak them).
#
# Private denylist: point AUGUR_SCRUB_EXTRA at newline-separated extended
# regexes, or at a file of them. When it is empty, the extra step is skipped
# and the script says so. Patterns and matched text are never echoed: a hit
# is reported as file:line only.
set -euo pipefail

if [ "${1:-}" = "--self-test" ]; then
  self="$(cd "$(dirname "$0")" && pwd)/scrub.sh"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$tmp" init -q

  # A clean file must pass. Loopback literals are allowed and blanked before
  # matching: IPv4 loopback and wildcard, and the IPv6 loopback ::1.
  printf 'listen on http://127.0.0.1:9093 or 0.0.0.0\n' > "$tmp/ok.txt"
  printf 'listen on [::1]:9093\n' > "$tmp/ok6.txt"
  printf '12:34:56 is a time, std::string is not an address, .locale is a word\n' > "$tmp/ok7.txt"
  printf 'see https://example.com/docs and localhost:9093\n' > "$tmp/ok8.txt"
  git -C "$tmp" add ok.txt ok6.txt ok7.txt ok8.txt
  out="$(cd "$tmp" && bash "$self" 2>&1 >/dev/null)" || { echo "self-test: clean file was flagged: $out" >&2; exit 1; }

  # AUGUR_SCRUB_EXTRA unset: the script must say so and still pass.
  (cd "$tmp" && bash "$self" >/dev/null 2>&1) || { echo "self-test: failed with no extra patterns" >&2; exit 1; }

  # Every pattern class must catch its sample, with loopback noise to prove
  # the blanking does not hide a real address on the same line.
  for bad in \
    'peer http://127.0.0.1:9093 and 10.20.30.40' \
    'host.example.ts.net 127.0.0.1' \
    '/Users/someone 127.0.0.1' \
    'printer.example.lan 127.0.0.1' \
    'peer http://[fe80::1]:9093 and 127.0.0.1' \
    'gateway 2001:db8::1 127.0.0.1' \
    'node dead:beef:0000:0000:0000:0000:0000:0001 127.0.0.1' \
    'link fe80::1%en0 127.0.0.1'
  do
    printf '%s\n' "$bad" > "$tmp/bad.txt"
    git -C "$tmp" add bad.txt
    out="$(cd "$tmp" && bash "$self" 2>&1 >/dev/null)" && { echo "self-test: missed: $bad" >&2; exit 1; }
  done
  rm -f "$tmp/bad.txt"

  # Extra patterns from the env must apply and must never be echoed, in the
  # output or in the exit path.
  bad='token sk-averyprivatedenylistvalue 127.0.0.1'
  printf '%s\n' "$bad" > "$tmp/bad.txt"
  git -C "$tmp" add bad.txt
  out="$(cd "$tmp" && AUGUR_SCRUB_EXTRA='sk-averyprivatedenylistvalue' bash "$self" 2>&1 >/dev/null)" \
    && { echo "self-test: extra pattern missed" >&2; exit 1; }
  case "$out" in *sk-averyprivatedenylistvalue*) echo "self-test: extra pattern was echoed" >&2; exit 1 ;; esac

  echo "scrub self-test: ok"
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"

patterns=(
  '([0-9]{1,3}\.){3}[0-9]{1,3}'   # IPv4 (127.0.0.1 and 0.0.0.0 are allowed below)
  '([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}'                     # IPv6, full form
  '([0-9A-Fa-f]{1,4}:){2,6}:([0-9A-Fa-f]{1,4}:?){0,4}|([0-9A-Fa-f]{1,4}::)([0-9A-Fa-f]{1,4}:?)+' # IPv6, compressed forms (a bare hex word before :: is a known
                                  # false-positive shape, e.g. std::cin; hits are file:line for review)
  '\.ts\.net'                      # tailnet names
  '\.local([^A-Za-z0-9_-]|$)'      # mDNS suffixes
  '\.lan([^A-Za-z0-9_-]|$)'        # .lan suffixes
  '/Users/[A-Za-z]'                # macOS home paths
  '/home/[a-z]'                    # Linux home paths
)
# Loopback and wildcard literals are blanked out *before* matching, so a real
# address on the same line is still caught. Run twice: adjacent literals
# share a boundary. ::1 is blanked with the same boundary guard, so
# 2001:db8::1 is never mistaken for it.
blank() {
  sed -E \
    -e 's/(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0)([^0-9.]|$)/\1_\3/g' \
    -e 's/(^|[^0-9A-Fa-f:])::1([^0-9A-Fa-f:]|$)/\1_\2/g' \
    | sed -E \
    -e 's/(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0)([^0-9.]|$)/\1_\3/g' \
    -e 's/(^|[^0-9A-Fa-f:])::1([^0-9A-Fa-f:]|$)/\1_\2/g'
}

extra="${AUGUR_SCRUB_EXTRA:-}"
if [ -n "$extra" ]; then
  if [ -f "$extra" ]; then
    while IFS= read -r line; do [ -n "$line" ] && patterns+=("$line"); done < "$extra"
    printf 'scrub: extra patterns loaded from file\n' >&2
  else
    while IFS= read -r line; do [ -n "$line" ] && patterns+=("$line"); done <<< "$extra"
    printf 'scrub: extra patterns loaded from env\n' >&2
  fi
else
  printf 'scrub: AUGUR_SCRUB_EXTRA not set; extra patterns skipped\n' >&2
fi

fail=0
while IFS= read -r -d '' f; do
  case "$f" in LICENSE-*|go.sum|scripts/scrub.sh) continue ;; esac
  [ -f "$f" ] || continue
  for p in "${patterns[@]}"; do
    # Print only file:line: never the pattern, never the matched text.
    hits=$(blank < "$f" | grep -nE -- "$p" | cut -d: -f1 || true)
    if [ -n "$hits" ]; then
      while IFS= read -r n; do printf 'scrub: %s:%s\n' "$f" "$n" >&2; done <<< "$hits"
      fail=1
    fi
  done
done < <(git ls-files -co --exclude-standard -z)

[ "$fail" -eq 0 ] && echo "scrub: clean"
exit "$fail"
