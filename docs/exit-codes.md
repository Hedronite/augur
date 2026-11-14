# Exit codes

| Code | Meaning |
| --- | --- |
| `0` | GREEN |
| `1` | YELLOW |
| `2` | RED |
| `3` | Bad or unsupported input. Malformed JSON, an unsupported payload shape (an Alertmanager webhook message or a Grafana contact-point payload), or an empty/missing input file. No verdict is produced. |
| `4` | Invalid policy. The policy file was read but fails schema validation, uses unknown keys, or sets `default: GREEN`. `validate` reports every error, not just the first. |
| `5` | Configuration or startup error. For example an unreadable `--policy` file (missing, no permission or over the size cap), an invalid `--now`, `serve` with a non-loopback Alertmanager URL, or a missing output path. |
| `6` | Internal error. Panics are recovered and exit `6`, so a crash can never read as a RED verdict. |

## Contract

- Only **"0–2 versus 3 and up"** is the public contract. Code meanings *within*
  3–6 may be refined; never rely on 3 vs 4 vs 5 in scripts.
- **Exit `1` collides with generic failure in `set -e` scripts.** Consumers that
  branch on YELLOW should parse the JSON output (`--json`) instead of branching on
  the exit code alone.
- A classification always produces a verdict and exits 0, 1 or 2. Errors never
  produce a verdict and never exit 0, 1 or 2.
- `--quiet` prints nothing and only sets the exit code; `--json` prints the verdict
  document alone on stdout. Errors always go to stderr.
