# wraith

Fully automated overnight bug bounty recon scanner — enumerate subdomains, probe live hosts, scan for vulnerabilities, capture screenshots, hunt secrets, and get notified when new findings appear.

---

## What's Included

| Script | Purpose |
|---|---|
| `recon.sh` | Core recon — runs all 11 phases against a single target |
| `monitor.sh` | Continuous monitoring — diffs runs, sends alerts, manages multiple targets |
| `installer.sh` | Auto-detects and installs every required tool |

---

## Quick Start

```bash
git clone https://github.com/benjaminbencsik/wraith.git
cd wraith
chmod +x *.sh

# Install all tools (auto-detects OS)
./installer.sh

# Run recon against a target
./recon.sh example.com

# Run in background overnight
nohup ./recon.sh example.com &
```

Results are saved next to the script, organized by target and timestamp:

```
recon/
└── example.com/
    └── 20240429_020000/
        ├── subdomains/
        ├── live/
        ├── ports/
        ├── web/
        ├── vulns/
        ├── secrets/
        ├── screenshots/
        └── SUMMARY.md
```

---

## Tool Installer (`installer.sh`)

Checks every required tool on startup and installs anything missing — no manual setup needed.

```bash
./installer.sh              # Check and install missing tools
./installer.sh --check-only # Just report what's missing
./installer.sh --force      # Skip confirmation prompt
./installer.sh --go-only    # Only install Go-based tools
```

Supports Ubuntu/Debian, RHEL/Fedora, Arch, and macOS (Homebrew). Automatically installs Go if it isn't present.

---

## Recon Pipeline (`recon.sh`)

Runs 11 phases sequentially. Safe to leave running overnight.

```bash
./recon.sh <domain> [output-dir]

# Examples
./recon.sh example.com
nohup ./recon.sh example.com > /dev/null 2>&1 &
./recon.sh example.com /custom/output/path
```

### Phases

```
Phase  1 — Subdomain Enumeration     subfinder + assetfinder + findomain
Phase  2 — Live Host Detection        httpx (status, title, tech stack)
Phase  3 — Port Scanning              nmap (36 common ports, -sV -sC)
Phase  4 — URL & Endpoint Collection  gau + waybackurls + katana
Phase  5 — Directory Fuzzing          ffuf (auto-downloads wordlist if missing)
Phase  6 — Vulnerability Scanning     nuclei (critical / high / medium + tag scans)
Phase  7 — XSS Scanning               dalfox on all parameterized URLs
Phase  8 — Open Redirect Testing      curl-based payload injection
Phase  9 — Secret Scanning            trufflehog + regex on downloaded JS
Phase 10 — Screenshots                gowitness on all live hosts
Phase 11 — Subdomain Takeover         nuclei takeover templates
```

A `SUMMARY.md` is written at the end with counts for every category.

---

## Continuous Monitoring (`monitor.sh`)

Runs `recon.sh` on a schedule, diffs each run against the last, and notifies you of anything new.

```bash
# Single target
./monitor.sh -t example.com

# Multiple targets from a file
./monitor.sh -f targets.txt

# With Slack or Discord notifications
./monitor.sh -t example.com --slack "https://hooks.slack.com/services/..."
./monitor.sh -t example.com --discord "https://discord.com/api/webhooks/..."

# Install as a nightly cron job (runs at 2am)
./monitor.sh -t example.com --install-cron

# Dry run — no scan, just show what would happen
./monitor.sh -t example.com --dry-run
```

Or configure notifications via environment variables:

```bash
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export NOTIFY_EMAIL="you@example.com"
```

Every run is diffed against the previous one — new subdomains, live hosts, vulnerabilities, XSS hits, open redirects, takeover candidates, and secrets all trigger alerts.

### Multi-target file format (`targets.txt`)

```
# One domain per line, # for comments
example.com
api.targetcorp.com
```

---

## Legal & Ethics

Only run against targets you have explicit written permission to test. The authors are not responsible for misuse of this tool.

---

## License

MIT
