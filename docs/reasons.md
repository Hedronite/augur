# Reason codes

Augur verdicts carry machine-readable reason codes. The enum is **closed**: a code
must be added to [`schema/verdict.v0.json`](../schema/verdict.v0.json) before the
engine can emit it, and the same enum is shared by the top-level rollup and
per-alert reasons.

## Top-level rollup (`reasons[]` in `augur.verdict/v0`)

| Code | Severity effect | Meaning |
| --- | --- | --- |
| `watchdog_only` | GREEN | A Watchdog heartbeat was seen and nothing else is firing. GREEN requires this heartbeat. |
| `watchdog_missing` | YELLOW | No Watchdog alert in the snapshot. An empty input array counts as not seen. Well-formed but blind input is a verdict, not an error. |
| `observability_blind` | RED | The Watchdog has not been seen, or a source has been unreachable, for longer than the policy's `deadman_window`. Produced by `serve` only. |
| `source_unreachable` | none by itself | A configured source could not be reached at classification time. Combined with a missed heartbeat past `deadman_window` it contributes to `observability_blind`. |
| `source_stale` | none by itself | A source was reached but is not producing current data. |

## Per-alert codes (`alerts[].reasons[]`)

| Code | Severity effect | Meaning |
| --- | --- | --- |
| `heartbeat` | GREEN, exempt | The Watchdog alert itself. Always `expected: true`. |
| `rule_matched` | from the rule | Matched a policy rule; the alert's severity is the rule's severity. The matched rule id is in `rule_id`. |
| `unmatched_default` | YELLOW | Matched no policy rule; the policy `default` severity applies. |
| `held_expected_dark` | exempt | Matched an `expected_dark` hold; never raises `overall`. |
| `held_known` | exempt | Matched a `known_hold`; never raises `overall`. |
| `held_announced_dark` | exempt | Matched an `announced_dark` hold still inside its `expires_at` window. |
| `announced_dark_expired` | YELLOW | An announced dark whose `expires_at` has passed; the exemption is over. |
| `silenced` | exempt | The alert is silenced in Alertmanager; shown but does not raise `overall`. |
| `inhibited` | exempt | The alert is inhibited; shown but does not raise `overall`. |
| `node_exporter_within_hold` | YELLOW | Unexpected `NodeExporterDown` before `node_exporter_red_hold` has elapsed. |
| `node_exporter_down_single_view` | RED | A first-class host's `NodeExporterDown` is still active past the hold, reported by one view. |
| `node_exporter_down_both_views` | RED | The same, confirmed by both views. Once two replicas report, both must agree before RED. |
| `clock_skew` | state | The alert's `starts_at` is in the future; hold age is clamped at 0. |
| `unmapped_host` | state | The host label is missing or is not a valid slug (`^[a-z0-9-]{1,32}$`); the alert's `host` field is the literal value `unmapped`. Raw label values are never echoed. |

## Semantics

- A single alert can stack codes, for example `rule_matched` + `clock_skew`, or a
  hold code alongside a state code.
- When a `NodeExporterDown` alert passes the hold and escalates to RED, the RED code
  (`node_exporter_down_single_view` or `node_exporter_down_both_views`) replaces
  `node_exporter_within_hold` on that alert.
- Codes on an exempt alert (`expected: true`) never raise `overall`; the top-level
  rollup reports heartbeat and source state, and alert-driven causes are detailed
  per alert. `overall` is the worst severity of any alert not exempted above.
- Output is sorted and stable: `alerts[]` by `(host, name, starts_at)`, `reasons[]`
  and `replicas[]` sorted. The same input gives byte-identical output.
