# LogWatch 📋

**System log anomaly detector — installed as a CLI command.**

Parses Linux auth logs and flags suspicious activity: brute-force attacks, successful intrusions, root logins, after-hours access, privilege escalations, new accounts, and port scans. Outputs a colour-coded terminal report or clean JSON.

```
╭──────────────────────────────────╮
│ LogWatch  v1.0                   │
│ System Log Anomaly Detector      │
│ Source: /var/log/auth.log        │
╰──────────────────────────────────╯

──────────────── Overview ─────────────────

   Log entries parsed       3,847
   Failed logins              412
   Successful logins           39
   Anomalies found              6
   Severity       🔴 1 critical  🟠 2 high  🟡 3 medium

─────────────── Top Attacking IPs ─────────────────

  IP Address         Failed Attempts
  45.33.32.156       382   ██████████████████████████████
  198.51.100.77       18   ██

──────────────── Findings ─────────────────

  🔴 [CRITICAL]  SUCCESS after failures: 'admin' from 45.33.32.156
     This IP previously had failed attempts and then succeeded —
     possible successful brute-force attack.

  🟠 [HIGH]  New user created: 'backdoor'
     A new system user was added. Verify this was intentional.
```

---

## Installation

```bash
git clone https://github.com/kazim-45/logwatch.git
cd logwatch
pip install rich
pip install -e .
```

The `-e` flag installs in editable mode — the `logwatch` command points directly at your cloned folder, so any edits to the code take effect instantly without reinstalling.

---

## Usage

```bash
# Show help
logwatch --help

# Auto-detect system log (/var/log/auth.log or /var/log/secure)
logwatch

# Analyse a specific file
logwatch -f /var/log/auth.log

# Generate a sample log with real attack patterns and analyse it (no setup needed)
logwatch --demo

# Output findings as JSON
logwatch -f auth.log --json

# Save JSON report to a file
logwatch -f auth.log --json report.json

# Tune the brute-force threshold (default: 5 failed logins)
logwatch -f auth.log --threshold 3

# Change the burst detection window (default: 60 seconds)
logwatch -f auth.log --window 30

# Change after-hours window (default: 23:00–06:00)
logwatch -f auth.log --after-hours-start 20 --after-hours-end 7

# Needs sudo to read the real system log on most distros
sudo logwatch
```

---

## What it detects

| Finding | Severity | Description |
|---|---|---|
| Brute-force attack | 🔴 / 🟠 | IP with many failed logins — uses sliding time window, not just a total count |
| Successful brute-force | 🔴 | IP that failed then succeeded — likely compromised |
| Direct root SSH login | 🔴 | Root logging in directly over SSH (should never happen) |
| Account targeted | 🟠 | One username hit with many failures across multiple IPs |
| New user / group created | 🟠 | System account added — possible backdoor |
| Sudo failures | 🟡 / 🟠 | User trying sudo without permission |
| After-hours login | 🟡 | Successful login outside configured working hours |
| Privilege escalation (`su`) | 🟡 | User switching identity with `su` |
| Port scan signatures | 🟠 | SSH negotiation failures — typical of automated scanners |

---

## Supported log formats

- `/var/log/auth.log` — Debian, Ubuntu, Kali Linux
- `/var/log/secure` — RHEL, CentOS, Fedora, Rocky Linux
- journald ISO timestamp exports

---

## Output formats

**Terminal (default)** — colour-coded severity levels, sample matching log lines, top attacking IPs table, and an hourly activity heatmap showing when events were concentrated.

**JSON (`--json`)** — machine-readable output for piping into other tools, dashboards, or SIEM systems. Progress messages are routed to stderr so stdout is clean JSON and can be piped directly.

```bash
logwatch -f auth.log --json | jq '.findings[] | select(.severity=="critical")'
```

```json
{
  "generated_at": "2024-06-15T09:00:00",
  "stats": {
    "total": 3847,
    "failed": 412,
    "successful": 39,
    "top_ips": [["45.33.32.156", 382]]
  },
  "findings": [
    {
      "severity": "critical",
      "category": "brute_success",
      "title": "SUCCESS after failures: 'admin' from 45.33.32.156",
      "detail": "This IP previously had failed attempts and then succeeded...",
      "ip": "45.33.32.156",
      "user": "admin"
    }
  ]
}
```

---

## How it works

LogWatch runs 9 independent detectors against the parsed event set:

**Sliding window brute-force** — doesn't just count total failures. It finds the densest burst of failures within a configurable time window (default 60 seconds). 100 failures spread over a day is noise; 20 failures in 60 seconds is an active attack.

**Successful-after-failure detection** — the most important one. Cross-references every successful login against the full set of IPs that previously failed. If an IP fails 18 times and then gets in once, that single success is the critical alert — not the 18 failures. This is how real SOC analysts think.

**After-hours detection** — time-aware. Reads the timestamp from each log entry and flags successful logins outside configurable working hours, independently of any brute-force pattern.

**Port scan detection** — looks for SSH negotiation failures (banner exchange errors, key type mismatches) which are the fingerprint of automated scanners probing open ports before attempting auth.

---

## Project structure

```
logwatch/
├── logwatch_pkg/
│   ├── __init__.py
│   └── core.py          ← all detection logic
├── pyproject.toml       ← registers the logwatch command via pip
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Dependencies

- [`rich`](https://pypi.org/project/rich/) — terminal formatting, colour output, tables
- Python stdlib only for everything else (`re`, `json`, `argparse`, `collections`, `ipaddress`, `datetime`)

---

## Try the demo

No Linux auth log on hand? This generates a realistic log with embedded attack patterns — brute force, root login, port scan, a backdoor account, after-hours intrusion — then analyses it immediately:

```bash
logwatch --demo
```

---

## License

MIT — use it, fork it, build on it.

---

*Built by [kazim-45](https://github.com/kazim-45) — part of a cybersecurity CLI toolkit alongside [MetaHunter](https://github.com/kazim-45/MetaHunter), [MilkyWay-CTF](https://github.com/kazim-45/MilkyWay-CTF), and [PassAudit](https://github.com/kazim-45/passaudit).*
