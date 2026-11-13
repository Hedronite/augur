# Security Policy

## Supported versions

Augur is pre-release: no versions are published yet. Security fixes apply to the latest commit on `main` only.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (`Hedronite/augur`). Do not open a public issue for a security problem.

Please include:

- the affected command (`evaluate`, `validate`, `serve`) or file;
- the input or policy that triggers it (synthetic data only — scrub real hostnames, IPs, and secrets before sending);
- the observed behaviour versus the expected fail-closed behaviour;
- your assessment of impact.

You will get an acknowledgement, then a fix or a rejection with reasoning. Fixes land as pull requests on `main`; a release is tagged when one exists.

## Scope

**In scope:**

- Payload decoding and sniffing — malformed or hostile Alertmanager API responses must fail closed (error, no verdict), never crash to an exit code that reads as GREEN/YELLOW/RED.
- Policy parsing — unknown keys, invalid matchers, `default: GREEN`, regex behaviour.
- Verdict generation — exemptions and holds must never be bypassable by crafted labels; the reason-code enum is closed.
- CLI argument and file handling — secrets never accepted on argv; error messages never leak raw label values.
- CI supply chain — action pinning, token permissions, secret scrubbing.

**Out of scope:**

- Prometheus, Alertmanager, Grafana or any other upstream component — report to those projects.
- The deployment host, the off-repository real policy, or the polling configuration of a specific installation.
- Reports that require a non-default, undocumented configuration.

## Design posture

For context when judging severity:

- Augur is classify-and-advise only: it never changes alert state. Its first release has **no network listener** — `serve` reads the Alertmanager API on loopback only and refuses a non-loopback URL.
- The engine fails closed: malformed input, unsupported payloads and invalid policies are errors with no verdict; panics are recovered and exit with an internal-error code so a crash can never read as a verdict.
- Raw label values are never echoed into output or errors; `host` is reported as a slug or the literal `unmapped`.
- GREEN requires a Watchdog heartbeat; silence is a verdict (`watchdog_missing`, then RED past the dead-man window), never an implicit GREEN.

## Repository hygiene

This repository contains synthetic host slugs only. Real hostnames, IP addresses, tailnet names, and secrets do not belong in any file, commit, or PR. CI runs a scrub plus secret scanning; anything that slips through is treated as an incident — please report it immediately.
