# Changelog

All notable changes to Augur are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/); the
release workflow takes the body of a version's section as the release notes
and fails if the section is missing.

## [Unreleased]

## [0.1.2] - 2026-11-25

A consumer that validates verdicts or the `augur{}` block against a pinned
schema must refresh it before taking this release: both reason enums grew and
the verdict has new fields.

### Added

- Verdicts carry `observed`, `valid_for` and `declaration`. The policy takes
  an optional `declaration: sha256:<64 hex>` (or null), and `evaluate` takes
  `--valid-for SECONDS` (default 60).
- Reason codes `alerts_over_cap` and `escalate_within_hold`,
  `escalate_single_view`, `escalate_both_views`, `escalate_views_split`.
- `watchdog.deadman_since`, written by `serve` while the heartbeat is not
  current.

### Fixed

- A poll with more than 4,000 alerts was reported as
  `alertmanager_unreachable`. It is now `alerts_over_cap` with the source
  `stale`; no alerts are evaluated and the verdict is never GREEN.
- A restart of `serve` reset the dead-man window. It now carries over from the
  last verdict at `--out`. Time spent stopped counts, so a start long after the
  last verdict is RED on its first poll unless that poll sees the heartbeat.
- Escalating rules on alerts other than `NodeExporterDown` reported
  `node_exporter_*` codes. They now report `escalate_*`.

### Changed

- CI: `scripts/check-vendor.sh` runs as a `vendor` job and in `make gate`. It
  checks each vendored file against the sha256 in `SOURCE` and against the
  bytes at the recorded upstream commit.

## [0.1.1] - 2026-11-14

The first published release. The program is unchanged from the unpublished
v0.1.0; only the release pipeline changed.

### Fixed

- Release: the release job could not attest the SBOMs. The attestation action
  accepts a CycloneDX file only if it has a `serialNumber`, and the SBOMs were
  written without one so that they would stay reproducible. Each SBOM now
  carries a deterministic `serialNumber` (`urn:uuid:` plus a UUIDv5 over the
  content), so the SBOMs and `SHA256SUMS` are still byte-identical on any host,
  and the release build checks every SBOM against the action's acceptance rule
  before anything is published.

### Changed

- Release: the SBOM attestations use `actions/attest` (the `attest-sbom` action
  is deprecated), pinned by commit SHA.
- CI: the reproducibility job builds all four targets, once from a tagged and
  once from an untagged checkout, and compares the binaries, the tarballs and
  the SBOMs.

## [0.1.0] - 2026-11-14

Tagged, not published: the release job failed at the SBOM attestation. Use v0.1.1.

First release: a deterministic classifier for Prometheus Alertmanager alerts.

### Added

- `augur evaluate` classifies one saved Alertmanager v2 alert set against a
  policy and prints a verdict: `GREEN`, `YELLOW` or `RED` with
  machine-readable reason codes. `--json` prints the canonical
  `augur.verdict/v0` document; `--quiet` sets only the exit code;
  `--now RFC3339` makes a run deterministic.
- `augur validate` checks a policy (`augur.policy/v0`, YAML) and reports
  every error, not just the first.
- `augur serve` polls the Alertmanager API on a literal loopback address and
  keeps a verdict file current atomically (temp file, fsync, rename). Every
  poll writes a verdict, including failed polls; the source states are
  `ok`, `unreachable` and `stale`; a missed heartbeat past the dead-man
  window is RED `observability_blind`.
- The watch rules: Watchdog-heartbeat-only GREEN, peer-Prometheus loss
  YELLOW, `NodeExporterDown` escalating to RED past its configurable hold
  for first-class hosts, expected-dark / known / announced-dark holds, the
  replicas (two-view) rule with split and lost-replica cases, silenced and
  inhibited alerts shown but not raising.
- Fail-closed everywhere: unknown input, unsupported payloads and invalid
  policies are errors, never verdicts; panics are recovered and exit 6 so a
  crash can never read as a verdict.
- Schemas as contracts: `augur.verdict/v0`, `augur.policy/v0` and the
  Alertmanager v2 input, with golden fixtures for every watch rule and
  fail-closed branch.
- Vigil fields: the verdict maps into `vigil.summary/v0` as a `verdicts[]`
  entry plus a bounded `augur{}` block (exact counts, raising alerts capped
  at 50 with an `omitted` count).
- Deployment: an example hardened systemd unit, operational runbook
  (`docs/operations.md`), install guide, release and verification docs.
- Release engineering: reproducible four-platform tarballs, CycloneDX SBOMs,
  keyless build-provenance attestations, and a CI job that rebuilds twice to
  prove reproducibility.
- Measured performance budgets with benchmarks and a soak test
  (`docs/performance.md`).
