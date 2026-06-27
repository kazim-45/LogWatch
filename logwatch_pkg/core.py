#!/usr/bin/env python3
"""
LogWatch — System Log Anomaly Detector
Parses Linux auth logs and flags suspicious activity:
brute-force attempts, privilege escalations, new IP logins,
after-hours access, and more.
"""

import re
import sys
import json
import argparse
import ipaddress
from pathlib import Path
from datetime import datetime, time as dtime
from collections import defaultdict, Counter

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    from rich.text import Text
    from rich.padding import Padding
except ImportError:
    print("Missing dependency. Run: pip install rich")
    sys.exit(1)

console = Console()

# ── Thresholds (tunable via --config) ────────────────────────────────────────

DEFAULTS = {
    "brute_force_threshold":    5,    # failed logins from one IP within window
    "brute_force_window_secs":  60,   # seconds for brute-force window
    "user_fail_threshold":      8,    # failed attempts on one username
    "after_hours_start":        23,   # 11 PM
    "after_hours_end":          6,    # 6 AM
    "new_ip_alert":             True,
    "max_report_entries":       50,
}

# ── Regex patterns for common log formats ────────────────────────────────────

# Standard syslog timestamp: "Jun 15 03:12:44"
RE_TIMESTAMP = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

PATTERNS = {
    # Failed password / auth failure
    "failed_login": re.compile(
        r"(?:Failed password|authentication failure|Invalid user|FAILED LOGIN)"
        r".*?(?:from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?"
        r".*?(?:for\s+(?:invalid user\s+)?(?P<user>\S+))?"
        r".*?(?:from\s+(?P<ip2>\d{1,3}(?:\.\d{1,3}){3}))?",
        re.IGNORECASE,
    ),
    # Successful login
    "successful_login": re.compile(
        r"(?:Accepted password|Accepted publickey|session opened)"
        r".*?(?:for\s+(?:user\s+)?(?P<user>\S+))?"
        r".*?(?:from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?",
        re.IGNORECASE,
    ),
    # sudo / privilege escalation
    "sudo_use": re.compile(
        r"sudo.*?(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$",
        re.IGNORECASE,
    ),
    "sudo_fail": re.compile(
        r"sudo.*?(?P<user>\S+)\s*:.*?(?:incorrect password|3 incorrect|NOT in sudoers)",
        re.IGNORECASE,
    ),
    # su
    "su_success": re.compile(
        r"su.*?Successful su for (?P<target>\S+) by (?P<user>\S+)",
        re.IGNORECASE,
    ),
    # New user / group created
    "new_user": re.compile(
        r"new user:\s*name=(?P<user>\S+)",
        re.IGNORECASE,
    ),
    "new_group": re.compile(
        r"new group:\s*name=(?P<group>\S+)",
        re.IGNORECASE,
    ),
    # SSH disconnect / connection closed abruptly
    "connection_closed": re.compile(
        r"(?:Disconnected from|Connection closed by)\s+(?:invalid user\s+)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    ),
    # Root login
    "root_login": re.compile(
        r"(?:Accepted password|Accepted publickey).*?for\s+root\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    ),
    # Session opened for root
    "root_session": re.compile(
        r"session opened for user root",
        re.IGNORECASE,
    ),
    # CRON jobs (for context)
    "cron": re.compile(r"CRON", re.IGNORECASE),
    # Port scan signatures (many connections, no auth)
    "possible_scan": re.compile(
        r"(?:Unable to negotiate|no matching|banner exchange|kex error)",
        re.IGNORECASE,
    ),
}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# ── Log entry dataclass ───────────────────────────────────────────────────────

class LogEntry:
    __slots__ = ("raw", "timestamp", "host", "service", "message", "line_no")

    def __init__(self, raw, timestamp, host, service, message, line_no):
        self.raw       = raw
        self.timestamp = timestamp
        self.host      = host
        self.service   = service
        self.message   = message
        self.line_no   = line_no

    def hour(self):
        return self.timestamp.hour if self.timestamp else None


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_timestamp(m, year=None):
    if not m:
        return None
    try:
        month = MONTHS.get(m.group("month"), 1)
        day   = int(m.group("day"))
        h, mi, s = map(int, m.group("time").split(":"))
        y = year or datetime.now().year
        return datetime(y, month, day, h, mi, s)
    except Exception:
        return None


def parse_log_file(filepath: Path) -> list:
    entries = []
    year = datetime.now().year

    RE_SYSLOG = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        r"\s+(?P<host>\S+)\s+(?P<service>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )
    RE_JOURNALD = re.compile(
        r"^(?P<year>\d{4})-(?P<month_n>\d{2})-(?P<day_n>\d{2})"
        r"T(?P<time>\d{2}:\d{2}:\d{2}).*?\s+(?P<host>\S+)\s+(?P<service>\S+):\s*(?P<message>.*)$"
    )

    try:
        text = filepath.read_text(errors="replace")
    except PermissionError:
        console.print(f"[red]Permission denied:[/] {filepath} — try running with sudo")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"[red]File not found:[/] {filepath}")
        sys.exit(1)

    for i, line in enumerate(text.splitlines(), 1):
        line = line.rstrip()
        if not line:
            continue

        # Try standard syslog format
        m = RE_SYSLOG.match(line)
        if m:
            ts_m = RE_TIMESTAMP.match(line)
            ts   = parse_timestamp(ts_m, year)
            entries.append(LogEntry(
                raw=line, timestamp=ts,
                host=m.group("host"), service=m.group("service").strip(),
                message=m.group("message"), line_no=i,
            ))
            continue

        # Try journald ISO format
        m2 = RE_JOURNALD.match(line)
        if m2:
            try:
                ts = datetime(
                    int(m2.group("year")), int(m2.group("month_n")), int(m2.group("day_n")),
                    *map(int, m2.group("time").split(":")),
                )
            except Exception:
                ts = None
            entries.append(LogEntry(
                raw=line, timestamp=ts,
                host=m2.group("host"), service=m2.group("service"),
                message=m2.group("message"), line_no=i,
            ))
            continue

        # Fallback: store raw, no timestamp
        entries.append(LogEntry(
            raw=line, timestamp=None,
            host="", service="", message=line, line_no=i,
        ))

    return entries


# ── Detectors ────────────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self, cfg: dict):
        self.cfg      = cfg
        self.findings = []   # list of Finding dicts

    def _add(self, severity, category, title, detail, entries=None, ip=None, user=None):
        self.findings.append({
            "severity": severity,   # critical / high / medium / low / info
            "category": category,
            "title":    title,
            "detail":   detail,
            "entries":  entries or [],
            "ip":       ip,
            "user":     user,
        })

    def run(self, entries: list):
        self._detect_brute_force(entries)
        self._detect_user_bruteforce(entries)
        self._detect_root_login(entries)
        self._detect_after_hours(entries)
        self._detect_sudo_failures(entries)
        self._detect_privilege_escalation(entries)
        self._detect_new_accounts(entries)
        self._detect_port_scan(entries)
        self._detect_successful_after_failures(entries)
        return self.findings

    # 1. IP-based brute force
    def _detect_brute_force(self, entries):
        ip_failures = defaultdict(list)

        for e in entries:
            m = PATTERNS["failed_login"].search(e.message)
            if not m:
                continue
            ip = m.group("ip") or m.group("ip2") if hasattr(m, "group") else None
            if not ip:
                # Try secondary extraction
                ip_m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", e.message)
                ip = ip_m.group(1) if ip_m else None
            if ip:
                ip_failures[ip].append(e)

        threshold = self.cfg["brute_force_threshold"]
        window    = self.cfg["brute_force_window_secs"]

        for ip, evts in ip_failures.items():
            evts_ts = [e for e in evts if e.timestamp]
            evts_ts.sort(key=lambda e: e.timestamp)

            # Sliding window
            max_in_window = 0
            burst_entries = []
            for i, e in enumerate(evts_ts):
                window_evts = [
                    x for x in evts_ts[i:]
                    if (x.timestamp - e.timestamp).total_seconds() <= window
                ]
                if len(window_evts) > max_in_window:
                    max_in_window = len(window_evts)
                    burst_entries = window_evts

            total = len(evts)
            if total >= threshold:
                sev = "critical" if total >= threshold * 4 else "high"
                self._add(
                    sev, "brute_force",
                    f"Brute-force from {ip}",
                    f"{total} failed login attempts (burst: {max_in_window} in {window}s window)",
                    entries=burst_entries[:5],
                    ip=ip,
                )

    # 2. Username-targeted brute force
    def _detect_user_bruteforce(self, entries):
        user_failures = defaultdict(list)

        for e in entries:
            m = PATTERNS["failed_login"].search(e.message)
            if not m:
                continue
            user_m = re.search(
                r"(?:for\s+(?:invalid user\s+)?|user=)([a-zA-Z0-9_\-\.]+)", e.message
            )
            if user_m:
                user = user_m.group(1)
                if user not in ("password", "from", "invalid", "user"):
                    user_failures[user].append(e)

        thresh = self.cfg["user_fail_threshold"]
        for user, evts in user_failures.items():
            if len(evts) >= thresh:
                self._add(
                    "high", "user_bruteforce",
                    f"Account targeted: '{user}'",
                    f"{len(evts)} failed attempts on this username",
                    entries=evts[:5],
                    user=user,
                )

    # 3. Root login via SSH
    def _detect_root_login(self, entries):
        for e in entries:
            m = PATTERNS["root_login"].search(e.message)
            if m:
                ip = m.group("ip")
                self._add(
                    "critical", "root_login",
                    f"Direct root SSH login from {ip}",
                    "Root should never log in directly over SSH. "
                    "Use a normal user + sudo instead.",
                    entries=[e], ip=ip, user="root",
                )
            elif PATTERNS["root_session"].search(e.message):
                self._add(
                    "high", "root_session",
                    "Root session opened",
                    "A session was opened for root — check if this is expected.",
                    entries=[e], user="root",
                )

    # 4. After-hours successful logins
    def _detect_after_hours(self, entries):
        start = self.cfg["after_hours_start"]
        end   = self.cfg["after_hours_end"]

        for e in entries:
            if not e.timestamp:
                continue
            h = e.timestamp.hour
            is_after_hours = (h >= start) or (h < end)
            if not is_after_hours:
                continue

            m = PATTERNS["successful_login"].search(e.message)
            if m:
                user_m = re.search(
                    r"for\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)", e.message
                )
                user = user_m.group(1) if user_m else "unknown"
                ip_m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", e.message)
                ip   = ip_m.group(1) if ip_m else None

                self._add(
                    "medium", "after_hours",
                    f"After-hours login: '{user}' at {e.timestamp.strftime('%H:%M')}",
                    f"Successful login at {e.timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"(outside {end:02d}:00–{start:02d}:00)",
                    entries=[e], ip=ip, user=user,
                )

    # 5. Sudo failures
    def _detect_sudo_failures(self, entries):
        sudo_fails = defaultdict(list)
        for e in entries:
            m = PATTERNS["sudo_fail"].search(e.message)
            if m:
                user_m = re.search(r"([a-zA-Z0-9_\-\.]+)\s*:", e.message)
                user = user_m.group(1) if user_m else "unknown"
                sudo_fails[user].append(e)

        for user, evts in sudo_fails.items():
            sev = "high" if len(evts) >= 3 else "medium"
            self._add(
                sev, "sudo_fail",
                f"Sudo failure: '{user}' ({len(evts)} attempts)",
                "User attempted sudo without correct credentials or without sudoers access.",
                entries=evts[:3], user=user,
            )

    # 6. Privilege escalation (su)
    def _detect_privilege_escalation(self, entries):
        for e in entries:
            m = PATTERNS["su_success"].search(e.message)
            if m:
                self._add(
                    "medium", "privesc",
                    f"su: '{m.group('user')}' → '{m.group('target')}'",
                    f"User switched identity using su.",
                    entries=[e],
                    user=m.group("user"),
                )

    # 7. New user / group accounts
    def _detect_new_accounts(self, entries):
        for e in entries:
            m = PATTERNS["new_user"].search(e.message)
            if m:
                self._add(
                    "high", "new_account",
                    f"New user created: '{m.group('user')}'",
                    "A new system user was added. Verify this was intentional.",
                    entries=[e], user=m.group("user"),
                )
            m2 = PATTERNS["new_group"].search(e.message)
            if m2:
                self._add(
                    "medium", "new_account",
                    f"New group created: '{m2.group('group')}'",
                    "A new system group was added.",
                    entries=[e],
                )

    # 8. Port scan signatures
    def _detect_port_scan(self, entries):
        scan_ips = defaultdict(list)
        for e in entries:
            if PATTERNS["possible_scan"].search(e.message):
                ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", e.message)
                if ip_m:
                    scan_ips[ip_m.group(1)].append(e)

        for ip, evts in scan_ips.items():
            if len(evts) >= 3:
                self._add(
                    "high", "port_scan",
                    f"Possible port scan from {ip}",
                    f"{len(evts)} SSH negotiation failures — typical of automated scanners.",
                    entries=evts[:3], ip=ip,
                )

    # 9. Successful login after multiple failures (likely successful brute-force)
    def _detect_successful_after_failures(self, entries):
        fail_ips = set()
        for e in entries:
            m = PATTERNS["failed_login"].search(e.message)
            if m:
                ip_m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", e.message)
                if ip_m:
                    fail_ips.add(ip_m.group(1))

        for e in entries:
            m = PATTERNS["successful_login"].search(e.message)
            if m:
                ip_m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", e.message)
                if ip_m and ip_m.group(1) in fail_ips:
                    ip = ip_m.group(1)
                    user_m = re.search(r"for\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)", e.message)
                    user = user_m.group(1) if user_m else "unknown"
                    self._add(
                        "critical", "brute_success",
                        f"SUCCESS after failures: '{user}' from {ip}",
                        "This IP previously had failed attempts and then succeeded — "
                        "possible successful brute-force attack.",
                        entries=[e], ip=ip, user=user,
                    )


# ── Stats collector ───────────────────────────────────────────────────────────

def collect_stats(entries: list) -> dict:
    total         = len(entries)
    failed        = 0
    successful    = 0
    ip_counter    = Counter()
    user_counter  = Counter()
    hour_counter  = Counter()
    services      = Counter()

    for e in entries:
        if PATTERNS["failed_login"].search(e.message):
            failed += 1
            ip_m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", e.message)
            if ip_m:
                ip_counter[ip_m.group(1)] += 1

        if PATTERNS["successful_login"].search(e.message):
            successful += 1

        if e.timestamp:
            hour_counter[e.timestamp.hour] += 1

        if e.service:
            services[e.service.strip()] += 1

    return {
        "total":      total,
        "failed":     failed,
        "successful": successful,
        "top_ips":    ip_counter.most_common(5),
        "hour_dist":  dict(hour_counter),
        "services":   services.most_common(5),
    }


# ── Report renderer ───────────────────────────────────────────────────────────

SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}
SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def render_report(findings: list, stats: dict, source: str, cfg: dict):
    console.print()
    console.print(Panel.fit(
        f"[bold white]LogWatch[/]  [dim]v1.0[/]\n"
        f"[dim]System Log Anomaly Detector\n"
        f"Source: {source}[/]",
        border_style="dim",
    ))

    # ── Overview ──
    console.print()
    console.rule("[bold]Overview[/]")
    console.print()

    sev_counts = Counter(f["severity"] for f in findings)
    total_findings = len(findings)

    if total_findings == 0:
        console.print("  [green]✓ No anomalies detected.[/]  Log looks clean.\n")
    else:
        ov = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        ov.add_column(width=20)
        ov.add_column()

        ov.add_row("[dim]Log entries parsed[/]",   f"[bold]{stats['total']:,}[/]")
        ov.add_row("[dim]Failed logins[/]",         f"[bold]{stats['failed']:,}[/]")
        ov.add_row("[dim]Successful logins[/]",     f"[bold]{stats['successful']:,}[/]")
        ov.add_row("[dim]Anomalies found[/]",       f"[bold]{total_findings}[/]")
        ov.add_row(
            "[dim]Severity breakdown[/]",
            "  ".join(
                f"[{SEV_COLOR[s]}]{SEV_ICON[s]} {sev_counts[s]} {s}[/]"
                for s in SEV_ORDER if sev_counts[s]
            ),
        )
        console.print(ov)

    # ── Top attacking IPs ──
    if stats["top_ips"]:
        console.print()
        console.rule("[bold]Top Attacking IPs[/]")
        console.print()
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        t.add_column("IP Address",  width=18)
        t.add_column("Failed Attempts", justify="right", width=18)
        t.add_column("Note", style="dim")
        for ip, count in stats["top_ips"]:
            note = ""
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    note = "private/internal"
                elif addr.is_loopback:
                    note = "loopback"
            except Exception:
                pass
            bar = "█" * min(count, 30)
            t.add_row(ip, str(count), f"{bar} {note}")
        console.print(t)

    # ── Findings ──
    if findings:
        findings_sorted = sorted(
            findings,
            key=lambda f: SEV_ORDER.index(f["severity"])
        )

        console.print()
        console.rule("[bold]Findings[/]")

        for f in findings_sorted[:cfg["max_report_entries"]]:
            sev   = f["severity"]
            color = SEV_COLOR[sev]
            icon  = SEV_ICON[sev]

            console.print()
            console.print(f"  {icon} [{color}][{sev.upper()}][/]  [bold]{f['title']}[/]")
            console.print(f"     [dim]{f['detail']}[/]")

            if f["entries"]:
                console.print(f"     [dim]Sample log lines:[/]")
                for e in f["entries"][:3]:
                    ts  = e.timestamp.strftime("%b %d %H:%M:%S") if e.timestamp else "??"
                    msg = e.message[:100] + ("…" if len(e.message) > 100 else "")
                    console.print(f"     [dim]  [{ts}] {msg}[/]")

        if len(findings) > cfg["max_report_entries"]:
            console.print(
                f"\n  [dim]… and {len(findings) - cfg['max_report_entries']} more findings "
                f"(use --json to see all)[/]"
            )

    # ── Activity heatmap ──
    if stats["hour_dist"]:
        console.print()
        console.rule("[bold]Hourly Activity[/]")
        console.print()
        max_val = max(stats["hour_dist"].values(), default=1)
        row1, row2 = "", ""
        for h in range(24):
            count = stats["hour_dist"].get(h, 0)
            bar_h = round((count / max_val) * 6) if max_val else 0
            blocks = "▇▆▅▄▃▂▁ "[max(0, 6 - bar_h)]
            row1 += blocks + " "
            row2 += f"{h:02d}" + " " if h < 10 else f"{h}" + " "
        console.print(f"  [dim]{row1}[/]")
        console.print(f"  [dim]{row2}[/]")
        console.print(f"  [dim]Hours (00–23), height = relative event count[/]")

    console.print()
    console.rule()
    console.print()


def render_json(findings: list, stats: dict, output_path: str = None):
    data = {
        "generated_at": datetime.now().isoformat(),
        "stats":        stats,
        "findings":     [
            {k: v for k, v in f.items() if k != "entries"}
            for f in findings
        ],
    }
    out = json.dumps(data, indent=2, default=str)
    if output_path:
        Path(output_path).write_text(out)
        console.print(f"[green]✓[/] JSON report saved to [bold]{output_path}[/]")
    else:
        print(out)


# ── Sample log generator (for demo / testing) ─────────────────────────────────

def generate_sample_log(path: Path):
    from random import randint, choice, seed
    seed(42)

    ips = ["192.168.1.105", "10.0.0.22", "45.33.32.156", "198.51.100.77", "203.0.113.4"]
    users = ["admin", "root", "kazim", "deploy", "ubuntu", "git"]

    now = datetime(2024, 6, 15, 0, 0, 0)
    lines = []

    def ts(hour, minute, second):
        return f"Jun 15 {hour:02d}:{minute:02d}:{second:02d}"

    # Normal daytime activity
    for i in range(10):
        lines.append(f"{ts(9, i*3, 0)} server sshd[1234]: Accepted password for kazim from 10.0.0.22 port 54321 ssh2")

    # Brute force from malicious IP (03:00 AM — after hours)
    for i in range(18):
        user = choice(["admin", "root", "ubuntu"])
        lines.append(f"{ts(3, i//3, i*3 % 60)} server sshd[1235]: Failed password for {user} from 45.33.32.156 port {40000+i} ssh2")

    # Successful login after brute force (the scary one)
    lines.append(f"{ts(3, 7, 12)} server sshd[1235]: Accepted password for admin from 45.33.32.156 port 40999 ssh2")

    # Root login
    lines.append(f"{ts(3, 8, 0)} server sshd[1236]: Accepted password for root from 198.51.100.77 port 22 ssh2")

    # After-hours login
    lines.append(f"{ts(2, 15, 0)} server sshd[1240]: Accepted password for deploy from 203.0.113.4 port 55123 ssh2")

    # Sudo failures
    for i in range(4):
        lines.append(f"{ts(4, i, 0)} server sudo[9900]: deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")

    # New user created
    lines.append(f"{ts(4, 30, 0)} server useradd[9999]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash")

    # Port scan signatures
    for i in range(5):
        lines.append(f"{ts(1, i*2, 0)} server sshd[2001]: Unable to negotiate with 203.0.113.4 port {1024+i}: no matching host key type found")

    # su escalation
    lines.append(f"{ts(10, 0, 0)} server su[8888]: Successful su for root by kazim")

    # Normal evening activity
    for i in range(5):
        lines.append(f"{ts(17, i*5, 0)} server sshd[3001]: Accepted publickey for kazim from 10.0.0.22 port 54400 ssh2")

    path.write_text("\n".join(lines) + "\n")
    console.print(f"[green]✓[/] Sample log written to [bold]{path}[/]  ({len(lines)} entries)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="logwatch",
        description="LogWatch — System log anomaly detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  logwatch                              Auto-detect system log
  logwatch -f /var/log/auth.log         Analyse a specific file
  logwatch --demo                       Generate a sample log and analyse it
  logwatch -f auth.log --json           Output findings as JSON
  logwatch -f auth.log --json out.json  Save JSON report to file
  logwatch -f auth.log --threshold 3    Flag IPs with 3+ failures (default: 5)

Supported log formats:
  /var/log/auth.log   (Debian / Ubuntu)
  /var/log/secure     (RHEL / CentOS / Fedora)
  journald exports    (ISO timestamp format)
        """,
    )
    parser.add_argument("-f", "--file",       help="Log file to analyse")
    parser.add_argument("--demo",             action="store_true", help="Generate sample log and run analysis")
    parser.add_argument("--json",             nargs="?", const="-", metavar="OUTPUT",
                                              help="Output as JSON (optionally save to file)")
    parser.add_argument("--threshold",        type=int, default=DEFAULTS["brute_force_threshold"],
                                              help="Failed login threshold for brute-force detection")
    parser.add_argument("--window",           type=int, default=DEFAULTS["brute_force_window_secs"],
                                              help="Time window in seconds for burst detection")
    parser.add_argument("--after-hours-start",type=int, default=DEFAULTS["after_hours_start"],
                                              help="After-hours start (24h, default 23)")
    parser.add_argument("--after-hours-end",  type=int, default=DEFAULTS["after_hours_end"],
                                              help="After-hours end (24h, default 6)")
    args = parser.parse_args()

    cfg = {
        **DEFAULTS,
        "brute_force_threshold":    args.threshold,
        "brute_force_window_secs":  args.window,
        "after_hours_start":        args.after_hours_start,
        "after_hours_end":          args.after_hours_end,
    }

    # Demo mode
    if args.demo:
        demo_path = Path("/tmp/logwatch_demo.log")
        generate_sample_log(demo_path)
        log_path = demo_path
    elif args.file:
        log_path = Path(args.file)
    else:
        # Auto-detect
        candidates = [
            Path("/var/log/auth.log"),
            Path("/var/log/secure"),
            Path("/var/log/syslog"),
        ]
        log_path = next((p for p in candidates if p.exists()), None)
        if not log_path:
            console.print("[red]No log file found.[/] Specify one with [bold]-f[/] or use [bold]--demo[/].")
            sys.exit(1)

    json_mode = args.json is not None
    err = Console(stderr=True) if json_mode else console

    err.print(f"\n[dim]Parsing [bold]{log_path}[/]...[/]")
    entries = parse_log_file(log_path)
    err.print(f"[dim]  → {len(entries):,} entries loaded[/]")
    err.print(f"[dim]Running anomaly detectors...[/]")

    detector = AnomalyDetector(cfg)
    findings = detector.run(entries)
    stats    = collect_stats(entries)

    if json_mode:
        output_file = None if args.json == "-" else args.json
        render_json(findings, stats, output_file)
    else:

        render_report(findings, stats, str(log_path), cfg)


if __name__ == "__main__":
    main()
