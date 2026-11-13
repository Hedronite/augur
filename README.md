# Augur

Augur reads alerts from Prometheus Alertmanager and classifies them as `GREEN`, `YELLOW` or `RED`, with a machine-readable reason for each verdict. It only advises: it never silences, acknowledges or routes alerts.

Status: pre-release. Nothing to install yet.

Not related to [AugurProject/augur](https://github.com/AugurProject/augur).

## What it does

Augur turns the current alert state into a deterministic verdict:

- **GREEN** — the Watchdog heartbeat is seen and nothing unexpected is firing.
- **YELLOW** — something needs attention: one Prometheus of the pair lost, an unexpected `NodeExporterDown` within its escalation window, an unexpected SSH failure, disk warnings, or any alert no rule matches.
- **RED** — observability is gone or failing closed: a first-class host's `NodeExporterDown` past the escalation hold, or the Watchdog silent past the dead-man window.

The engine is pure and deterministic: `Evaluate(snapshot, policy, now) → Verdict` with no I/O, so the same input and the same `now` produce byte-identical output. It fails closed on unknown input or an invalid policy, and it never emits GREEN without a Watchdog heartbeat.

Augur is classify-and-advise only. Silencing, acknowledgement, inhibition, routing and notifications stay with Alertmanager. There is no UI, no direct probing of hosts, and no disk checking of its own — it classifies *alerts* about those things.

## Where it fits

Augur sits beside the Simplex → Vigil → Facet triad. Vigil's `overall` is the worse of the Simplex and Augur verdicts, and Augur verdicts reach Facet only as fields inside `vigil.summary/v0`. Augur is the single owner of the rules derived from alerts (Watchdog-only GREEN, peer-Prometheus YELLOW, node_exporter past its hold RED); Simplex keeps its probe-side checks.

## The verdict document

Every classification produces an `augur.verdict/v0` document — schema, `generated_at`, `time_source`, `overall`, `policy_sha256`, top-level rollup reasons, Watchdog heartbeat state, source states, and one entry per alert with its own severity and reason codes. The contract is [`schema/verdict.v0.json`](schema/verdict.v0.json); the full reason-code table is in [`docs/reasons.md`](docs/reasons.md).

Short version of the rollup:

| Code | Overall | Meaning |
| --- | --- | --- |
| `watchdog_only` | GREEN | Heartbeat seen, nothing else firing. |
| `watchdog_missing` | YELLOW | No Watchdog in the snapshot; an empty array counts as not seen. |
| `observability_blind` | RED | Watchdog silent or a source unreachable past the dead-man window (`serve` only). |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` / `1` / `2` | GREEN / YELLOW / RED |
| `3`+ | Bad or unsupported input, invalid policy, config error, internal error |

Only "0–2 versus 3 and up" is the public contract, and exit `1` collides with generic failure in `set -e` scripts — see [`docs/exit-codes.md`](docs/exit-codes.md).

## Quick start (planned, A1)

These commands are the A0 contract shape; they are not implemented yet.

```sh
# Classify one saved snapshot of the Alertmanager v2 /api/v2/alerts response.
augur evaluate --alerts alerts.json --policy policy.yaml

# Check a policy; reports every error, not just the first.
augur validate --policy policy.yaml

# Poll Alertmanager on loopback and write the verdict atomically.
augur serve --policy policy.yaml --alertmanager http://localhost:9093 --out verdict.json
```

`evaluate` takes an optional `--now RFC3339` for deterministic runs. Human-readable output is the default; `--json` prints the document alone on stdout; `--quiet` prints nothing and only sets the exit code.

## Security

Augur has no network listener in its first release: `serve` reads the Alertmanager API on loopback only and refuses a non-loopback URL. It never changes alert state, never echoes raw label values, and never takes secrets on the command line. See [SECURITY.md](SECURITY.md) to report a vulnerability. The repository contains synthetic host slugs only (`host-a` … `host-e`); alert names follow the real rule set and are public by design. The real policy lives off-repository.

## Contributing

Contributions follow the DCO; see [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, the commit rules, and the error-message house style.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
