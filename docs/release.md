# How a release is built

Every `v*` tag on this repository produces a reproducible release: four
platform tarballs, one CycloneDX SBOM per tarball, and a `SHA256SUMS`. This
page explains how the release is produced, how to rebuild it yourself and
compare byte for byte, and how to verify the checksums, attestations and
SBOMs.

## What a release contains

- `augur_v0.1.0_<os>_<arch>.tar.gz` for linux/amd64, linux/arm64,
  darwin/amd64 and darwin/arm64.
- `augur_v0.1.0_<os>_<arch>.sbom.cdx.json` — a CycloneDX 1.6 SBOM per
  tarball.
- `SHA256SUMS` — sorted, two-space format, covering the four tarballs and the
  four SBOMs.

The version string is the tag as written (`v0.1.0`); the binary prints
`augur v0.1.0` (`augur version` or `--version`), and assets are named with
it. Each tarball holds one top directory `augur_v0.1.0_<os>_<arch>/` with:
`augur` (0755), `LICENSE-APACHE`, `LICENSE-MIT`, `README.md`,
`deploy/augur.service`, `schema/` and `examples/`. Files are 0644, owner and
group 0, and their mtime is the tagged commit's time.

## How it is built

The release workflow (`release.yml`) runs on a `v*` tag push and produces the
release. Its build step is the same recipe a local build uses:

```
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= \
  -X github.com/Hedronite/augur/internal/cli.version=v0.1.0"
```

The Go toolchain is pinned to an exact patch version — the one recorded in
the release notes (1.27.4 for v0.1.0). **A different Go patch version changes
the binary**, so a faithful rebuild starts with the pinned toolchain.

The same recipe is runnable locally:

```sh
make release VERSION=v0.1.0     # output in dist/
```

`make release` calls `scripts/release.sh`, the same script CI calls; the
archive writer is a small Go program, so it does not depend on GNU tar. The
tarballs are deterministic: sorted entries, mtime fixed from
`SOURCE_DATE_EPOCH` (the tagged commit's time), numeric owner 0, and
`gzip -n` with no original name or timestamp in the header.

The SBOMs come from `cyclonedx-gomod` v1.12.0 (`app -std`, no serial and no
timestamp), so the SBOM files are reproducible too. They list exactly the
modules in the binary — its direct dependencies and the Go standard library
at the toolchain version — not test-only modules. That tool was chosen over
a scanner because it reads the module graph of the very binary build rather
 than guessing from source, and it is one pinned Go module with no
vulnerability database to trust.

## The dry run

Running `release.yml` through `workflow_dispatch` (input `version`, default
`v0.1.0`) is a **dry run**: it builds, checksums and makes the SBOMs, then
uploads everything as a workflow artifact named `release-dry-run`. It creates
no release and no attestation.

Everything a dry run produces is byte-identical to the tag run on the same
commit: the tarballs, the binaries, the SBOMs and the whole `SHA256SUMS`. (The
SBOM tool records two things that depend on where it ran, and
`scripts/sbom.sh` normalises both: the digests of the tool's own binary, which
differ per build platform, are dropped from `metadata.tools` (its name and
version stay); and the main component's version, which the tool stamps from
the VCS state, is pinned to the version being built. The tool is run without a serial number so its output is
reproducible, but the attestation action refuses a CycloneDX file that has no
`serialNumber`, so the script adds one that is derived from the content:
`urn:uuid:` plus a UUIDv5 over the sha256 of the SBOM exactly as written
without that key. `python3 -I scripts/sbomtool.py accept <file>` recomputes it
and applies the action's own acceptance rule. With all of this, the SBOMs, and
so the whole `SHA256SUMS`, are the same on any host.)

## Rebuild it yourself

```sh
git clone https://github.com/Hedronite/augur && cd augur
git checkout v0.1.0
# with Go 1.27.4 (or the patch named in the release notes) on PATH
make release VERSION=v0.1.0                  # writes dist/
```

Then compare your tarballs with the published ones. Download the published
`SHA256SUMS` somewhere else, so it does not overwrite the one `make release`
wrote:

```sh
mkdir -p /tmp/augur-published
curl -fsSL -o /tmp/augur-published/SHA256SUMS \
  https://github.com/Hedronite/augur/releases/download/v0.1.0/SHA256SUMS

# Linux: sha256sum; macOS: shasum -a 256
(cd dist && sha256sum augur_v0.1.0_*.tar.gz) \
  | diff - <(grep '\.tar\.gz$' /tmp/augur-published/SHA256SUMS) && echo "tarballs match"
```

The comparison that must hold is the **tarball lines**: no output from `diff`
means the bytes are identical. A difference means the bytes differ: check the
Go patch version first. A local `make release` writes only the tarballs; the
SBOM lines of the published `SHA256SUMS` come from `make sbom`, which needs
`cyclonedx-gomod` at the pinned version (`scripts/install-cyclonedx.sh` installs it
and checks its module hash) and is not part of the rebuild check.

## Verify what you downloaded

```sh
# checksums (after downloading the assets you want)
sha256sum -c SHA256SUMS --ignore-missing

# build provenance, cryptographically bound to the repository
gh attestation verify augur_v0.1.0_linux_amd64.tar.gz --repo Hedronite/augur

# the SBOM, bound to its tarball
gh attestation verify augur_v0.1.0_linux_amd64.tar.gz --repo Hedronite/augur \
  --predicate-type https://cyclonedx.org/bom

# the checksum file itself
gh attestation verify SHA256SUMS --repo Hedronite/augur
```

Download with `gh release download v0.1.0 --repo Hedronite/augur --pattern
'…'` or plain `curl -fsSLO
https://github.com/Hedronite/augur/releases/download/v0.1.0/<asset>`. The
attestations are keyless: there is no key and no secret to keep, and `gh
attestation verify` checks them against GitHub's transparency log.

## What the workflow is allowed to do

The dry run runs with read-only permissions: it creates no release and no
attestation. Only the tag-triggered publish job holds write scopes
(`contents`, `id-token`, `attestations`); every other job and workflow stays
`contents: read`, and every action is pinned by full SHA. A CI job named
`repro` builds linux/amd64 twice in separate checkout paths with separate
caches and fails if the binary or tarball sha256 differ, so the
reproducibility claim is checked on every change, not just at release time.
