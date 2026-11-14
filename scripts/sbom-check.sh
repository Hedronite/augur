#!/usr/bin/env bash
# sbom-check.sh — prove a CycloneDX SBOM describes exactly what the binary was
# built from.
#
#   usage: scripts/sbom-check.sh BINARY SBOM
#
# The binary is the authority. `go version -m` reports the main module, every
# dependency module and the Go toolchain, and the SBOM has to agree with it:
#
#   - every dependency the binary reports is a component, by purl
#     pkg:golang/<path>@<version>;
#   - the Go standard library appears as std@<toolchain>, and the toolchain
#     versions match line for line;
#   - the main module is metadata.component, not a component;
#   - no component names a module the binary does not carry, so a stale or
#     over-broad SBOM fails instead of passing quietly.
#
# Only module paths, versions and purls are ever printed. The script reads no
# environment variable, no token and no path beyond its two arguments, and it
# writes one temporary file under TMPDIR that it removes on exit.
#
# Needs bash and python3; it runs on the bash 3.2 that ships with macOS and on
# any Linux shell. Nothing here depends on GNU coreutils.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") BINARY SBOM" >&2
  echo "  BINARY  an executable built with the Go toolchain" >&2
  echo "  SBOM    the CycloneDX JSON SBOM for that binary" >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 1
fi

binary="$1"
sbom="$2"

if [ ! -f "$binary" ]; then
  echo "sbom-check: no such binary: $binary" >&2
  exit 1
fi
if [ ! -f "$sbom" ]; then
  echo "sbom-check: no such SBOM: $sbom" >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "sbom-check: go is not on PATH; it reads the binary's build info" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "sbom-check: python3 is not on PATH; it reads the SBOM" >&2
  exit 1
fi

buildinfo="$(mktemp "${TMPDIR:-/tmp}/sbom-check.XXXXXX")"
trap 'rm -f "$buildinfo"' EXIT HUP INT TERM

if ! go version -m "$binary" >"$buildinfo" 2>/dev/null; then
  echo "sbom-check: go version -m cannot read $binary; is it a Go binary?" >&2
  exit 1
fi

python3 -I - "$buildinfo" "$sbom" "$binary" <<'PY'
import json
import sys
from urllib.parse import unquote

PURL = "pkg:golang/"


def read_buildinfo(path):
    """Return (toolchain, main path, main version, {path: version})."""
    toolchain = main_path = main_version = None
    deps = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            # go version -m tab-indents every line but the first.
            line = line.rstrip("\n").lstrip("\t")
            if not line:
                continue
            fields = line.split("\t")
            kind = fields[0]
            if kind == "path" and len(fields) >= 2:
                main_path = fields[1]
            elif kind == "mod" and len(fields) >= 2:
                main_path = fields[1]
                main_version = fields[2] if len(fields) >= 3 else ""
            elif kind == "dep" and len(fields) >= 3:
                path, version = fields[1], fields[2]
                # A replaced module compiles as its replacement: dep old v => new v.
                if "=>" in fields:
                    arrow = fields.index("=>")
                    if len(fields) > arrow + 2:
                        path, version = fields[arrow + 1], fields[arrow + 2]
                deps[path] = version
            elif toolchain is None and ": " in line:
                toolchain = line.rsplit(": ", 1)[1].strip()
    return toolchain, main_path, main_version, deps


def parse_purl(purl):
    """Return (path, version) from a golang purl, or None.

    cyclonedx-gomod writes qualifiers and a subpath on every component
    (pkg:golang/x@v1?goarch=amd64&goos=linux&type=module), so both have to come
    off before the version can be read.
    """
    if not purl.startswith(PURL):
        return None
    body = purl[len(PURL):].split("#", 1)[0].split("?", 1)[0]
    body = unquote(body)
    if "@" not in body:
        return None
    path, version = body.rsplit("@", 1)
    return path, version


def read_sbom(path):
    """Return (main component, {path: version} for components, std version)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    components = {}
    std = None
    for c in doc.get("components") or []:
        parsed = parse_purl(c.get("purl") or "")
        if parsed is None:
            continue
        path, version = parsed
        if path == "std":
            std = version
            continue
        components[path] = version
    main = ((doc.get("metadata") or {}).get("component")) or {}
    return main, components, std


binary = sys.argv[3]
toolchain, main_path, main_version, deps = read_buildinfo(sys.argv[1])
main, components, std = read_sbom(sys.argv[2])

problems = []

if toolchain is None:
    problems.append("the binary reports no Go toolchain, so the std component cannot be checked")
elif std is None:
    problems.append("the SBOM has no std component; it must carry std@%s" % toolchain)
elif std != toolchain:
    problems.append("the SBOM says std@%s but the binary was built with %s" % (std, toolchain))

for path in sorted(deps):
    if path not in components:
        problems.append("missing from the SBOM: %s@%s" % (path, deps[path]))
    elif components[path] != deps[path]:
        problems.append("version differs for %s: binary %s, SBOM %s"
                        % (path, deps[path], components[path]))

for path in sorted(components):
    if path not in deps:
        problems.append("in the SBOM but not in the binary: %s@%s" % (path, components[path]))

parsed_main = parse_purl(main.get("purl") or "")
main_name, main_sbom_version = parsed_main if parsed_main else (main.get("name"), None)
if not main_name:
    problems.append("the SBOM has no metadata.component naming the main module")
elif main_path and main_name != main_path:
    problems.append("the SBOM's main module is %s, the binary was built from %s" % (main_name, main_path))
elif main_path and main_path in components:
    problems.append("the main module %s is listed as a component; it belongs in metadata.component" % main_path)

# The main module version comes from VCS stamping, so a dirty tree gives the
# two tools a different pseudo-version even when the code is the same. A tree
# that cannot produce a stable version cannot be attested either, so that case
# is reported and not failed; two concrete versions that disagree is a failure.
sbom_main_version = main.get("version") or main_sbom_version
VCS_ONLY = ("+dirty",)
if main_path and main_version and sbom_main_version and main_version != sbom_main_version:
    if any(v.endswith(VCS_ONLY[0]) for v in (main_version, sbom_main_version)) \
            or "(devel)" in (main_version, sbom_main_version):
        print("sbom-check: note: main module version is VCS-stamped and differs "
              "(binary %s, SBOM %s); a tagged clean build makes them equal"
              % (main_version, sbom_main_version), file=sys.stderr)
    else:
        problems.append("main module version differs: binary %s, SBOM %s"
                        % (main_version, sbom_main_version))

if problems:
    print("sbom-check: %s does not describe %s" % (sys.argv[2], binary), file=sys.stderr)
    for p in problems:
        print("sbom-check: " + p, file=sys.stderr)
    print("sbom-check: FAILED, %d problem(s)" % len(problems), file=sys.stderr)
    sys.exit(1)

print("sbom-check: ok — %d modules, std@%s, main %s %s"
      % (len(deps), toolchain, main_name, main.get("version", "")))
PY
