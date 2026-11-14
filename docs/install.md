# Installing Augur

Manual install of `augur serve` on a host running systemd. Every path below
is the one the example unit [`deploy/augur.service`](../deploy/augur.service)
uses; adjust both together if you move anything.

## What runs where

| Path | What it is |
| --- | --- |
| `/usr/local/bin/augur` | the binary, mode 0755 |
| `/etc/augur/policy.yaml` | the policy, mode **0640**, owner `root:augur` |
| `/var/lib/augur/verdict.json` | the verdict file Augur writes; systemd's `StateDirectory=augur` creates the directory |
| `/etc/systemd/system/augur.service` | the unit, copied from `deploy/augur.service` in the tarball |

Augur polls the Alertmanager v2 API on a **literal loopback address** and
holds no other network capability; it never changes alert state.

## Install

1. Download and verify the release — checksums and attestations — as
   described in [`release.md`](release.md). Pick the tarball for your
   platform.
2. Extract and install the binary:

   ```sh
   tar xzf augur_v0.1.0_linux_amd64.tar.gz
   install -m 0755 augur_v0.1.0_linux_amd64/augur /usr/local/bin/augur
   /usr/local/bin/augur version
   ```

3. Create the service user and the policy:

   ```sh
   useradd --system --home /var/lib/augur augur
   install -d -m 0750 -o root -g augur /etc/augur
   install -m 0640 -o root -g augur policy.yaml /etc/augur/policy.yaml
   ```

   The policy is validated at startup: `augur validate --policy
   /etc/augur/policy.yaml` should print `ok` before you go further.

4. Install the unit:

   ```sh
   install -m 0644 augur_v0.1.0_linux_amd64/deploy/augur.service /etc/systemd/system/augur.service
   systemctl daemon-reload
   systemctl enable --now augur
   ```

5. Verify:

   ```sh
   systemctl status augur            # active (running)
   /usr/local/bin/augur version      # augur v0.1.0
   cat /var/lib/augur/verdict.json   # a complete augur.verdict/v0 document
   ```

   The verdict file is rewritten every interval (default 30 s); check its
   mtime moves.

## Upgrade

1. Download and verify the new release (as above).
2. Keep the old binary for rollback, then replace and restart:

   ```sh
   mv /usr/local/bin/augur /usr/local/bin/augur.previous
   install -m 0755 augur_v0.1.0_linux_amd64/augur /usr/local/bin/augur
   systemctl restart augur
   ```

3. Verify the new version is running and the verdict is fresh:

   ```sh
   /usr/local/bin/augur version
   systemctl status augur
   python3 -c "import json;print(json.load(open('/var/lib/augur/verdict.json'))['apiVersion'], json.load(open('/var/lib/augur/verdict.json'))['generated_at'])"
   ```

   The policy is read once at startup: if the new release changed the policy
   schema, update `/etc/augur/policy.yaml` before restarting, or `serve`
   refuses to start (exit 4) with the old file and a new major.

## Rollback

The old binary is still on disk:

```sh
mv /usr/local/bin/augur /usr/local/bin/augur.failed
mv /usr/local/bin/augur.previous /usr/local/bin/augur
systemctl restart augur
```

Rolling the binary back also restores the old policy expectations; if the
policy file was upgraded for the new version, restore its previous content
too (keep a copy next to it, mode 0640, when you upgrade the policy).

## If it will not start

`augur serve` refuses to start (exit 5) with a house-style message when the
URL is not a literal loopback address, the policy is unreadable, the output
directory is unwritable, or the interval is out of bounds (5 s–60 s). A
readable but invalid policy exits 4 with every error listed. `journalctl -u
augur` carries the JSON logs; see [`operations.md`](operations.md) for the
full runbook.
