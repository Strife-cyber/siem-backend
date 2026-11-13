# Attack Simulation Harness

Proves that detection rules actually fire against real log data, end to end:

```
scenario JSON (raw log lines + time offsets)
  → siem-collector `replay` binary (real normalize_record + shipper)
  → POST /api/v1/logs → Elasticsearch
  → correlation cycle (BullMQ) → incidents → SOAR playbooks
  → assertions on incidents / playbook executions / SOAR actions
```

Nothing bypasses the production code path: replayed logs go through the exact
`normalize_record` Rust function and the exact batched shipper used by the live
collector, and the backend runs its real correlation rules, incident creation
and SOAR orchestration. The only substitution is the firewall agent, which the
simulation compose override points at an in-memory dry-run agent
(`SOAR_FIREWALL_PROVIDER=dry_run`) so scenarios do not need the pfSense /
Windows Defender lab.

## Running a scenario

Prerequisites:

1. Stack up with the simulation override (exposes Postgres/Redis ports and the
   dry-run firewall agent):

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.simulation.yml up -d --build
   ```

2. Rules seeded (from the repo root, with the DB port exposed):

   ```bash
   DATABASE_URL=postgresql://siem:siem_password@localhost:5432/siem_db npm run seed:rules
   ```

3. Collector replay binary built:

   ```bash
   cd ../siem-collector && cargo build --bin replay
   ```

Then:

```bash
npm run simulate -- simulation/scenarios/benign-baseline.json
npm run simulate -- simulation/scenarios/r001-brute-force.json
```

Useful options: `--api-url`, `--collector-bin`, `--db-url`, `--timeout`,
`--settle-ms`, `--batch-ms`, `--api-key` (see the header of `run.ts`).

## Gate scenarios

| Scenario | Proves |
|---|---|
| `benign-baseline.json` | Normal activity produces **zero** HIGH/CRITICAL incidents and no SOAR actions (false-positive gate). |
| `r001-brute-force.json` | 14 failed SSH logins from one IP fire R001, create an incident and execute `block_ip` end to end. |

Exit code is 0 when every assertion passes, 1 when any fails.

Note: correlation deduplicates identical detections for 5 minutes — reset the
DB (`docker compose down -v`) and re-seed if re-running the same scenario
immediately.

## Scenario file format

```json
{
  "name": "my-scenario",
  "description": "What it proves",
  "base_time": "2026-11-12T09:00:00Z",
  "requires_rules": ["R001"],
  "sources": [
    {
      "source_type": "LINUX_AUTH",
      "hostname": "KALI-01",
      "lines": [
        { "offset_seconds": 0, "raw": "Nov 12 09:00:01 kali sshd[1234]: Failed password for invalid user admin from 192.168.243.10 port 5555 ssh2" }
      ]
    }
  ],
  "assert": {
    "expect_incidents": [
      { "rule_id": "R001", "min_severity": "WARNING", "min_count": 1 }
    ],
    "expect_no_incidents_for_rules": ["R005"],
    "expect_no_high_or_critical_incidents": false,
    "expect_playbook_executions": [
      { "playbook_name": "block_ip", "status": "EXECUTED", "min_count": 1 }
    ],
    "expect_soar_actions": [
      { "action_type": "block_ip", "min_count": 1 }
    ]
  }
}
```

- `base_time` + `offset_seconds` (per line, may be fractional) set the
  `collected_at` timestamp the normalizer stamps on each log, so time-window
  rules see a realistic timeline. `normalized_at` is set by the backend at
  ingest time.
- `source_type` labels match the collector's serde labels (`LINUX_AUTH`,
  `NGINX_ACCESS`, `WINDOWS_SECURITY`, …). Anything unknown falls back to a
  custom source type.
- `requires_rules` activates those correlation rules before the run (they ship
  inactive after seeding).

## Capturing fixtures from the live lab

The current fixtures are written in the exact raw formats the collector's
parsers consume (Linux auth syslog lines, nginx combined format). To refresh
them with real lab captures:

1. Run the collector in WAL mode on the lab machines and let it collect.
2. Extract raw lines per source, e.g. from the collector's WAL dump
   (`cargo run --bin wal_dump`) or directly from `/var/log/auth.log`,
   `/var/log/nginx/access.log`, Windows event XML exports.
3. Paste the raw lines into a scenario's `lines` array with `offset_seconds`
   relative to the attack start time.

This keeps the proof chain honest: real collector format in, real backend
pipeline out.

## Deferred rules & correlations (telemetry gaps)

- **R009 Impossible Travel** — needs a GeoIP database; the collector emits no geo fields and no GeoIP service is configured. Deferred until geo enrichment exists.
- **R019 Firewall Modification** — the collector has no firewall *configuration-change* parser yet (pfSense config changes are not in filterlog; Windows 2004–2009 rule-change events are collected but not classified). Deferred until a config-change signal is normalized.
- **C004 / C005 / C009** — deferred: all three chains end in a data-exfiltration signal, and R003 needs per-user/per-flow outbound byte telemetry (`bytes_sent`) that no current collector source provides. pfSense filterlog carries only per-packet payload lengths (no cumulative bytes, no user attribution); honest per-flow bytes would need conntrack collection (new collector work). The chains cannot be simulation-proven until then.

## Implemented deferred rules (telemetry now available)

- **R012 Linux Shell Abuse** — auditd EXECVE telemetry (siem-collector): reverse shells, download-and-execute cradles, encoded payloads in `command_line`.
- **R016 SSH Persistence (authorized_keys)** — auditd PATH records: any `authorized_keys` file access.
- **R024 DNS Tunneling** — dnsmasq/unbound resolver telemetry: high volume + long/high-entropy domain names, aggregated per registered domain.
- **R025 Unusual Data Staging** — auditd PATH / Windows 4663 file operations: bursts of archive-file creation on one host. Content-level staging (reading sensitive files) still needs FIM/content telemetry; this detects the archive-aggregation signal.
