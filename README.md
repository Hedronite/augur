# Augur

Augur reads alerts from Prometheus Alertmanager and classifies them as `GREEN`, `YELLOW` or `RED`, with a machine-readable reason for each verdict. It only advises: it never silences, acknowledges or routes alerts.

Status: pre-release. `evaluate`, `validate` and `serve` are implemented.

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

Every classification produces an `augur.verdict/v0` document — `apiVersion`, `generated_at`, `time_source`, `overall`, `policy_sha256`, top-level rollup reasons, Watchdog heartbeat state, source states, and one entry per alert with its own severity and reason codes. The contract is [`schema/verdict.v0.json`](schema/verdict.v0.json); the full reason-code table is in [`docs/reasons.md`](docs/reasons.md).

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
| `3` | Bad or unsupported input (malformed JSON, an Alertmanager webhook message, a Grafana contact-point payload) |
| `4` | Invalid policy |
| `5` | Configuration or startup error |
| `6` | Internal error; panics are recovered here, so a crash never reads as a verdict |

Only "0–2 versus 3 and up" is the public contract, and exit `1` collides with generic failure in `set -e` scripts — see [`docs/exit-codes.md`](docs/exit-codes.md).

## Quick start

```sh
# Classify one saved snapshot of the Alertmanager v2 /api/v2/alerts response.
# Fixture 50 is a single-view snapshot whose NodeExporterDown is past its
# hold: the command prints the verdict below and exits 2 (RED).
augur evaluate \
  --alerts testdata/fixtures/50-node-exporter-past-hold-single-view/alerts.json \
  --policy testdata/fixtures/50-node-exporter-past-hold-single-view/policy.yaml \
  --now "$(cat testdata/fixtures/50-node-exporter-past-hold-single-view/now.txt)"

# Check a policy; reports every error, not just the first.
augur validate --policy examples/policy.yaml
```

`--now RFC3339` makes a run deterministic; without it, `evaluate` uses the wall clock and the verdict records which (`time_source`). Human-readable output is the default; `--json` prints the document alone on stdout; `--quiet` prints nothing and only sets the exit code. Errors go to stderr, name the file and field, show a short excerpt, and say how to fix it.

The run above prints:

```
OVERALL: RED
reasons: none
watchdog: seen, last 2026-01-15T11:58:00Z
sources: file ok (2 alerts, last ok 2026-01-15T12:00:00Z)
alerts:
  RED    NodeExporterDown  host-a  active  since 2026-01-15T11:45:00Z  rule node-exporter-down  reasons node_exporter_down_single_view,rule_matched
  GREEN  Watchdog          host-a  active  since 2025-12-01T00:00:00Z  -                        reasons heartbeat
```

Note on views: `examples/policy.yaml` declares two replicas (`r1`, `r2`) to show the two-view rules. A single-view deployment — today's — omits `replicas` entirely and runs in single-view mode.

## Serving

`augur serve` polls the Alertmanager v2 API and keeps a verdict file current for Vigil to read. Runbook-level detail is in [`docs/operations.md`](docs/operations.md).

```sh
augur serve \
  --policy /etc/augur/policy.yaml \
  --alertmanager http://127.0.0.1:9093 \
  --out /var/lib/augur/verdict.json \
  [--interval 30s]
```

- **Polling.** The first verdict is written straight away at startup, then one per interval. Every poll writes a verdict — including a failed one. A failed poll (connect error, timeout, non-200, refused redirect, an over-cap body, or a decode error) classifies an *empty* snapshot: `alerts: []`, the source `unreachable`, verdict YELLOW with `alertmanager_unreachable` and `watchdog_missing`, going RED `observability_blind` once the dead-man window passes. Old alerts are never reused as current.
- **`stale`.** A poll that succeeds but carries a Watchdog `updatedAt` older than `deadman_window` means Alertmanager is up while the alert source stopped refreshing: the source is marked `stale`, the Watchdog counts as not seen, and `alertmanager_stale` is added.
- **The URL.** `--alertmanager` must be `http://` to a *literal* loopback address (`127.0.0.0/8` or `[::1]`). `localhost` and other names are refused on purpose: resolving a name is a trust step Augur does not need.
- **Startup refusals (exit 5).** A non-loopback URL, an unreadable `--policy`, an unwritable `--out` directory, or an `--interval` outside 5 s–60 s (default 30 s; the bounds keep the file inside Vigil's 120 s `stale_after`). A readable but invalid policy is exit 4.
- **The file.** Written atomically — temp file, fsync, rename, directory fsync — mode 0644, canonical `augur.verdict/v0` JSON under Vigil's 4 MiB cap, never truncated: a verdict that would not fit is an internal error (exit 6) that leaves the last file in place.
- **Shutdown.** `SIGTERM`/`SIGINT` finish any write in progress and exit 0. A crash or panic leaves the last file untouched; Vigil ages a file that stops updating into `stale` after 120 s. There is no state file: a restart resets the dead-man clock.
- **Policy.** Read once at startup; there is no reload in v0. Restart to pick up a new policy. `SIGHUP` is logged and ignored.
- **Logs.** `log/slog` JSON on stderr: one line per poll and one per tracker state change — enum values and counts only, never label values or alert text.
- **Deployment.** [`deploy/augur.service`](deploy/augur.service) is an example systemd unit — not installed — with generic paths and a hardened sandbox.

## Security

Augur has no network listener: `serve` only *reads* the Alertmanager API on a literal loopback address and refuses anything else. It never changes alert state, never echoes raw label values, and never takes secrets on the command line. See [SECURITY.md](SECURITY.md) to report a vulnerability. The repository contains synthetic host slugs only (`host-a` … `host-e`); alert names follow the real rule set and are public by design. The real policy lives off-repository.

## Contributing

Contributions follow the DCO; see [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, the commit rules, and the error-message house style.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
