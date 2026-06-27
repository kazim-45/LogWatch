# LogWatch 📋

**System log anomaly detector — finds suspicious activity in Linux auth logs.**

Feed it your `/var/log/auth.log` and get a colour-coded threat report: brute-force attacks, successful intrusions, root logins, after-hours access, privilege escalations, new accounts, and port scans.

```
╭──────────────────────────────────╮
│ LogWatch  v1.0                   │
│ System Log Anomaly Detector      │
│ Source: /var/log/auth.log        │
╰──────────────────────────────────╯

──────────────── Overview ─────────────────

   Log entries parsed       3,847
   Failed logins            412
   Successful logins        39
   Anomalies found          6
   Severity breakdown       🔴 1 critical  🟠 2 high  🟡 3 medium

─────────────── Top Attacking IPs ─────────────────

  IP Address          Failed Attempts
  45.33.32.156        382   ██████████████████████████████████
  198.51.100.77       18    ██

──────────────── Findings ─────────────────

  🔴 [CRITICAL]  SUCCESS after failures: 'admin' from 45.33.32.156
     This IP previously had failed attempts and then succeeded —
     possible successful brute-force attack.

  🟠 [HIGH]  Brute-force from 45.33.32.156
     382 failed login attempts (burst: 14 in 60s window)

  🟠 [HIGH]  New user created: 'backdoor'
     A new system user was added. Verify this was intentional.
```

---

## What it detects

| Finding | Severity | Description |
|---|---|---|
| Brute-force attack | 🔴/🟠 | IP with many failed logins in a time window |
| Successful brute-force | 🔴 | IP that failed then succeeded — likely compromised |
| Direct root SSH login | 🔴 | Root logging in directly (should never happen) |
| After-hours login | 🟡 | Successful login between 11 PM and 6 AM |
| New user/group created | 🟠 | System account added — possible backdoor |
| Sudo failures | 🟡/🟠 | User trying sudo without permission |
| Privilege escalation (su) | 🟡 | User switching identity with `su` |
| Port scan signatures | 🟠 | SSH negotiation failures — typical of scanners |

---

## Supported log formats

- `/var/log/auth.log` — Debian, Ubuntu, Kali
- `/var/log/secure` — RHEL, CentOS, Fedora, Rocky
- journald ISO timestamp exports

---

## Installation

```bash
git clone https://github.com/kazim-45/logwatch.git
cd logwatch
pip install rich
```

No other dependencies — uses Python stdlib for everything else.

---

## Usage

```bash
# Auto-detect system log (/var/log/auth.log or /var/log/secure)
python logwatch.py

# Analyse a specific file
python logwatch.py -f /var/log/auth.log

# Generate a sample log with real attack patterns and analyse it
python logwatch.py --demo

# Output findings as JSON (pipe-friendly)
python logwatch.py -f auth.log --json

# Save JSON report to file
python logwatch.py -f auth.log --json report.json

# Tune the brute-force threshold (default: 5 failures)
python logwatch.py -f auth.log --threshold 3

# Change after-hours window (default: 23:00–06:00)
python logwatch.py -f auth.log --after-hours-start 20 --after-hours-end 7

# On Linux — needs sudo to read /var/log/auth.log
sudo python logwatch.py
```

---

## How it works

LogWatch parses each log line with regex, extracts structured events, then runs 9 independent detectors against the full event set:

**Brute-force detection** uses a sliding time window. It doesn't just count total failures — it finds the densest burst of failures within a configurable window (default 60 seconds) and flags the worst case. An IP with 100 failures spread over a day is different from 20 failures in 60 seconds.

**Successful-after-failure detection** is the most important one. It cross-references every successful login against the set of IPs that previously failed. If an IP failed 18 times then succeeded once, that's a probable intrusion, not a mistyped password.

**After-hours detection** is time-aware. It reads the timestamp from each log entry and flags successful logins that happen outside normal working hours. This is configurable — a 24/7 ops team would set different hours than a small office.

---

## Output formats

**Terminal (default):** colour-coded severity levels, sample log lines, hourly activity heatmap, top attacking IPs table.

**JSON (`--json`):** machine-readable output for piping into other tools, SIEM systems, or dashboards. The progress output goes to stderr so stdout is clean JSON.

```json
{
  "generated_at": "2024-06-15T09:00:00",
  "stats": {
    "total": 47,
    "failed": 18,
    "successful": 18,
    "top_ips": [["45.33.32.156", 18]]
  },
  "findings": [
    {
      "severity": "critical",
      "category": "brute_success",
      "title": "SUCCESS after failures: 'admin' from 45.33.32.156",
      "detail": "...",
      "ip": "45.33.32.156",
      "user": "admin"
    }
  ]
}
```

---

## Try the demo

Don't have a Linux auth log handy? Run:

```bash
python logwatch.py --demo
```

This generates a realistic sample log with embedded attack patterns — brute force, root login, port scan, a backdoor account, after-hours intrusion — then analyses it immediately.

---

## Dependencies

- [`rich`](https://pypi.org/project/rich/) — terminal formatting, colour output, tables
- Python stdlib only for everything else (`re`, `json`, `argparse`, `collections`, `ipaddress`, `datetime`)

---

## License

MIT — use it, fork it, build on it.

---

*Built by [kazim-45](https://github.com/kazim-45) — part of a cybersecurity CLI toolkit alongside [MetaHunter](https://github.com/kazim-45/MetaHunter), [MilkyWay-CTF](https://github.com/kazim-45/MilkyWay-CTF), and [PassAudit](https://github.com/kazim-45/passaudit).*
