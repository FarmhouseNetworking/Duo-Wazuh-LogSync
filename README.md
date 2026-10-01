# Duo-Wazuh-LogSync

Send **Cisco Duo** authentication, admin activity and telephony logs into a **self-hosted Wazuh manager** with one script. The script also installs a tested Wazuh ruleset, tagged for **NIST SP 800-171 / CMMC Level 2**.

It uses Duo's official [DuoLogSync](https://github.com/duosecurity/duo_log_sync) to pull logs from the Duo Admin API and send them as JSON to a syslog listener on the Wazuh manager. That listener accepts connections only from the manager itself (localhost). You don't need an agent, a public port or a custom decoder.

```
 Duo Admin API  --HTTPS 443-->  DuoLogSync (systemd)  --TCP 127.0.0.1:5140-->  wazuh-remoted
   (cloud)                        on the Wazuh manager                            |
                                                                    json decoder -> 9999_duo_rules.xml
```

| File | Purpose |
|---|---|
| `duo-wazuh-install.sh` | Installer for the command line (flags or environment variables) |
| `superops/duo-wazuh-install-superops.sh` | The same installer, set up for SuperOps RMM runtime variables |
| `rules/9999_duo_rules.xml` | Reference copy of the ruleset (the installer writes it for you) |

---

## What the installer does

1. Checks the server first: running as root, Wazuh manager present, Duo API reachable over 443, listener port free, rule IDs 120000–120039 not already used.
2. Installs DuoLogSync in a Python virtual environment at `/opt/duologsync`, under a dedicated `duologsync` service account with no login shell.
3. Writes the DuoLogSync config with mode `600`, since it holds your Duo secret key.
4. Backs up `ossec.conf` and any existing rules to `/root/duo-wazuh-backup-<timestamp>/`.
5. Adds a **localhost-only** `<remote>` syslog listener to `ossec.conf`, wrapped in marker comments so later runs and uninstall can find it.
6. Writes `/var/ossec/etc/rules/9999_duo_rules.xml`.
7. Runs `wazuh-analysisd -t`. **If validation fails, it rolls back automatically.**
8. Restarts the manager and confirms the listener is up.
9. Installs a systemd unit that restarts DuoLogSync whenever the manager restarts (see [why](#lessons-learned)).
10. Confirms the whole pipeline: the service is active, DuoLogSync is connected to `wazuh-remoted`, and sample auth and activity events pass through `wazuh-logtest`.

You can run it again safely. A second run updates DuoLogSync and replaces the listener and rules in place.

---

## Requirements

- Wazuh manager **4.x**, tested on **4.14**. It must be the manager, not an agent.
- Ubuntu/Debian (apt) or RHEL/Rocky/Alma (dnf/yum), with systemd and `python3`.
- Outbound HTTPS from the manager to `api-xxxxxxxx.duosecurity.com`. Duo Federal hosts (`duofederal.com`) are also supported.
- A Duo account with the **Owner** role, so you can create the Admin API application.

---

## Step 1: Create the Duo Admin API application

1. In the Duo Admin Panel, go to **Applications → Protect an Application** and search for **Admin API**.
2. Give it a name, for example `Wazuh-DuoLogSync`.
3. Under permissions, check **only** `Grant read log` (least privilege).
4. Copy the **Integration key**, **Secret key** and **API hostname**.

> The `activity` and `trustmonitor` logs depend on your Duo edition. If DuoLogSync's log shows permission errors, remove those endpoints.

---

## Step 2a: Run it from the command line

```bash
git clone https://github.com/FarmhouseNetworking/Duo-Wazuh-LogSync.git
cd Duo-Wazuh-LogSync
chmod +x duo-wazuh-install.sh

# Pass the secret through the environment so it stays out of shell history and the process list
read -rs DUO_SKEY && export DUO_SKEY
sudo -E ./duo-wazuh-install.sh \
  --ikey DIXXXXXXXXXXXXXXXXXX \
  --api-host api-xxxxxxxx.duosecurity.com
```

### Options

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--ikey` | `DUO_IKEY` | (none) | Required |
| `--skey` | `DUO_SKEY` | (none) | Required. Prefer the env var. |
| `--api-host` | `DUO_API_HOST` | (none) | Required |
| `--endpoints` | `DUO_ENDPOINTS` | `auth,telephony,activity` | Valid values: `auth`, `telephony`, `activity`, `trustmonitor` |
| `--offset-days` | `DLS_OFFSET_DAYS` | `180` | How many days of history to pull on the first run (max 180) |
| `--port` | `WAZUH_PORT` | `5140` | The localhost listener port |
| | `DLS_GIT_REF` | `master` | Pin a DuoLogSync tag if you prefer |

### Actions

```bash
sudo ./duo-wazuh-install.sh            # install / upgrade (default)
sudo ./duo-wazuh-install.sh status     # service, connection, Duo alert counts by rule
sudo ./duo-wazuh-install.sh resend     # clear checkpoints and pull the history window again
sudo ./duo-wazuh-install.sh uninstall  # remove service, listener and rules
sudo ./duo-wazuh-install.sh uninstall --purge   # ...also delete /opt/duologsync and its user
```

---

## Step 2b: Run it from SuperOps RMM

1. In SuperOps, go to **Scripts → New Script**, choose language **Bash** and platform **Linux**, and paste in `superops/duo-wazuh-install-superops.sh`.
2. Create these **runtime variables**. The names must match exactly:

| Variable | Required | Example |
|---|---|---|
| `DuoIntegrationKey` | yes | `DIXXXXXXXXXXXXXXXXXX` |
| `DuoSecretKey` | yes (mark it secure/masked) | `••••••••` |
| `DuoApiHost` | yes | `api-xxxxxxxx.duosecurity.com` |
| `DuoEndpoints` | no | `auth,telephony,activity` |
| `DuoOffsetDays` | no | `180` |
| `WazuhListenPort` | no | `5140` |
| `DuoAction` | no | `install`, `status`, `resend` or `uninstall` |

3. Run the script **as root** against the Wazuh manager asset.
4. The script exits `0` on success and `1` on any failure or warning, so SuperOps marks a broken install as failed. All output appears in the run log.

Tip: save a second copy of the script with `DuoAction=status`, and schedule it weekly as a health check for your compliance reporting.

---

## Rules

| ID | Level | Fires on | 800-171 tag |
|---|---|---|---|
| 120001 | 3 | Successful Duo authentication | 3.5.3 |
| 120002 | 5 | Denied/failed authentication (with Duo `reason`) | 3.5.3 |
| 120003 | 12 | User reported a push as **fraud** | 3.14.6 |
| 120004 | 10 | 5+ denials in 5 minutes for one user (MFA fatigue or brute force) | 3.1.8 |
| 120005 | 8 | Successful auth using a bypass code or remembered device | n/a |
| 120030 | 3 | Any Duo activity log event (admin logins, directory syncs, changes) | 3.3.1 |
| 120031 | 5 | Failed Duo Admin Panel login | 3.1.8 |
| 120032 | 10 | 3+ failed Admin Panel logins in 5 minutes | 3.1.8 |
| 120033 | 10 | Sensitive configuration change (integrations, admins, policies, bypass codes) | 3.4.3, 3.1.7 |
| 120034 | 8 | **Active Directory sync failed.** Users disabled in AD may still be active in Duo | 3.1.1, 3.5.6 |
| 120020/21 | 2 | Telephony credit usage. *These field matches haven't been confirmed against live data.* | n/a |

Filter in the Wazuh dashboard with `rule.groups: duo`.

---

## Lessons learned

We hit each of these in production. The script already handles all of them, and they're written down here so nobody has to rediscover them:

1. **Stock Suricata rule 86600 silently drops Duo auth events.** It matches any JSON event that has both `timestamp` and `event_type` fields, and Duo auth logs have both. Because 86600 is level 0, the events vanish without an error. The fix is to attach the Duo rules as children of 86600 (`if_sid 86600`), with a standalone fallback for events that don't match it.
2. **Name the rule file `9999_...`.** Wazuh sorts *all* rule files (stock and custom) together alphabetically. A custom file that sorts before the stock ruleset can't reference stock rules like 86600.
3. **`action` is a Wazuh static field.** `<field name="action">` makes analysisd fail with `Field 'action' is static`. Use `<action>` instead, or a dotted field such as `action.name`.
4. **DuoLogSync 2.4.x no longer accepts the `adminaction` endpoint.** Admin events now come from the **`activity`** endpoint, which uses a different layout (`action.name`, `actor.*`, `target.*`, `outcome.result`). An old endpoint list stops DuoLogSync before it even writes its log file.
5. **DuoLogSync never reconnects its TCP connection.** Restarting `wazuh-manager` kills the connection. DuoLogSync then sends its next batch into the dead connection, logs "successfully wrote all logs", and saves a checkpoint, so that batch is lost. Then it exits. The included systemd unit (`PartOf=wazuh-manager.service`, plus a wait for the listener before starting) prevents this.
6. **Frequency rules count by arrival time, not event time.** The first 180-day history pull arrives within seconds, so rules like 120004 can fire on old, unrelated events. Ignore frequency hits from the initial pull or from `resend`.
7. **RDP logins report `access_device.ip` as `0.0.0.0`.** Duo for Windows Logon (RDP) doesn't report a source IP, so the hostname is the only device identifier you get. Geo or impossible-travel detection won't work for those events.
8. **Wildcard greps catch the wrong thing.** `grep duo` also matches the `duologsync` service account's own sudo and useradd events. Filter on `"groups":["duo"` instead.

---

## Checking that it works

```bash
sudo ./duo-wazuh-install.sh status
```

Then do one Duo login and wait about 2–3 minutes for the next fetch (Duo's API runs a few minutes behind):

```bash
sudo grep '"groups":\["duo' /var/ossec/logs/alerts/alerts.json | tail -1
```

To see the raw events while troubleshooting, temporarily set `<logall_json>yes</logall_json>` in `ossec.conf` and restart the manager. Duo events show up in `archives.json` with `"location":"127.0.0.1"`. **Turn it off again afterwards**, because archives can fill the disk quickly.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `duologsync` exits immediately and creates no log file | Config validation failed. Run `sudo -u duologsync /opt/duologsync/venv/bin/duologsync /opt/duologsync/config.yml` to see the error. |
| The DuoLogSync log shows `ConnectionResetError` | The manager restarted while DuoLogSync was connected. Run `systemctl restart duologsync`. The unit file normally does this for you. |
| DuoLogSync shows "wrote" but there are no Duo alerts | Test a raw event with `wazuh-logtest`. If it matches rule 86600, the rules file is missing or loading in the wrong order. |
| Permission errors on `activity` or `trustmonitor` | Your Duo plan doesn't include that log. Remove it with `--endpoints auth,telephony`. |
| The installer says another `<remote>` already uses port 5140 | That's a listener someone added by hand (no marker comments). Remove that block from `ossec.conf` and run again, or use `--port`. |

## Security notes

- The secret key lives only in `/opt/duologsync/config.yml` (mode 600, owned by `duologsync`). Add the Admin API application to your credential-rotation schedule.
- The listener accepts connections only from `127.0.0.1` (`local_ip` and `allowed-ips`), so no new port is exposed on the network.
- The Admin API application only needs `Grant read log`.

## License

MIT. See [LICENSE](LICENSE). DuoLogSync is © Duo Security and MIT-licensed. This project is not affiliated with Cisco, Duo or Wazuh.

---

Built and maintained by [Farmhouse Networking](https://www.farmhousenetworking.com). We offer white-labeled Tier 3 support, RMM as a service and co-managed IT for MSPs. Questions: scott@farmhousenetworking.com
