# Reason codes

Augur verdicts carry machine-readable reason codes. The enum is **closed**: a code
must be added to [`schema/verdict.v0.json`](../schema/verdict.v0.json) before the
engine can emit it, and the same enum is shared by the top-level rollup and
per-alert reasons.

## Renames (2026-11-14)

Three published codes shared their names with codes Vigil adds to a verdict's
`reasons[]`, where the two meanings differ. They were renamed before any
consumer existed. No Augur code equals one of Vigil's own codes.

| Old code | New code | Where |
| --- | --- | --- |
| `source_unreachable` | `alertmanager_unreachable` | rollup |
| `source_stale` | `alertmanager_stale` | rollup |
| `clock_skew` (dead-man tracker: the evaluation clock appeared to run backwards) | `evaluation_clock_backwards` | rollup, `serve` only |
| `clock_skew` (per alert: `starts_at` in the future) | `alert_clock_skew` | per alert |

## Top-level rollup (`reasons[]` in `augur.verdict/v0`)

| Code | Severity effect | Meaning |
| --- | --- | --- |
| `watchdog_only` | GREEN | A Watchdog heartbeat was seen and nothing else is firing. GREEN requires this heartbeat. |
| `watchdog_missing` | YELLOW | No Watchdog alert in the snapshot. An empty input array counts as not seen. Well-formed but blind input is a verdict, not an error. |
| `observability_blind` | RED | The Watchdog has not been seen, or a source has been unreachable, for longer than the policy's `deadman_window`. Produced by `serve` only. |
| `alertmanager_unreachable` | none by itself | The Alertmanager source could not be reached at classification time. Combined with a missed heartbeat past `deadman_window` it contributes to `observability_blind`. |
| `alertmanager_stale` | none by itself | The Alertmanager source was reached but is not producing current data: the Watchdog's `updatedAt` is older than `deadman_window`. |
| `evaluation_clock_backwards` | state | `serve` only: the clock appeared to run backwards since the last observation. Elapsed time is treated as zero and the state never moves backwards. |

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
| `node_exporter_within_hold` | YELLOW | Unexpected `NodeExporterDown`: every reporting replica reports it, and the merged age is within `node_exporter_red_hold`. |
| `node_exporter_down_single_view` | RED | A first-class host's `NodeExporterDown` is still active past its hold as seen by one view: single-replica mode, or a declared replica that does not report it because it is lost, with every reporting replica past the hold. A lost replica does not block RED. |
| `node_exporter_down_both_views` | RED | The same alert confirmed: every declared replica reports it and the merged age is past the hold. |
| `node_exporter_views_split` | YELLOW | A declared replica is live and does not report the alert while another replica does. A path problem on one side alone, with a healthy peer, stays YELLOW. |
| `alert_clock_skew` | state | The alert's `starts_at` is in the future; hold age is clamped at 0. |
| `unmapped_host` | state | The host label is missing or is not a valid slug (`^[a-z0-9][a-z0-9-]{0,31}$`); the alert's `host` field is the literal value `unmapped`. Raw label values are never echoed. |

## The replicas rule

The optional policy key `replicas: [slug, …]` lists the views whose alerts reach
Augur's source, read from the label named by `replica_label`. If `replicas` is
unset, there is one unlabeled view (single-replica mode).

- A merged alert's `starts_at` is the **latest** start among the replicas reporting
  it: the moment all of them agreed. So `age = now − starts_at` stays truthful.
- A replica is **lost** when a `PeerPrometheusDown`/`PeerPrometheusAbsent` alert is
  active whose `replica_label` value names it. A lost replica never blocks RED.
- Case table:

  | Case | Verdict |
  | --- | --- |
  | Single view, past the hold | RED `node_exporter_down_single_view` |
  | Every declared replica reports it, merged age past the hold | RED `node_exporter_down_both_views` |
  | Every reporting replica reports it, merged age within the hold | YELLOW `node_exporter_within_hold` |
  | A declared replica is live and does not report it while another does | YELLOW `node_exporter_views_split` |
  | A declared replica is lost, and every reporting replica is past the hold | RED `node_exporter_down_single_view` |

## Semantics

- A single alert can stack codes, for example `rule_matched` + `alert_clock_skew`, or
  a hold code alongside a state code.
- When a `NodeExporterDown` alert passes the hold and escalates to RED, the RED code
  (`node_exporter_down_single_view` or `node_exporter_down_both_views`) replaces
  `node_exporter_within_hold` on that alert.
- Codes on an exempt alert (`expected: true`) never raise `overall`; the top-level
  rollup reports heartbeat and source state, and alert-driven causes are detailed
  per alert. `overall` is the worst severity of any alert not exempted above.
- Output is sorted and stable: `alerts[]` by `(host, name, starts_at)`, `reasons[]`
  and `replicas[]` sorted. The same input gives byte-identical output.
