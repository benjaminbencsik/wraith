#!/usr/bin/env bash
# =============================================================================
# monitor.sh — Continuous Bug Bounty Recon Monitor
# Runs recon.sh on a schedule, diffs results, and sends alerts.
#
# Usage:
#   Single target:   ./monitor.sh -t example.com
#   Multi-target:    ./monitor.sh -f targets.txt
#   Setup cron:      ./monitor.sh --install-cron
#   Check only:      ./monitor.sh -t example.com --dry-run
#
# Notification setup (set env vars or edit config below):
#   export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
#   export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
#   export NOTIFY_EMAIL="you@example.com"
# =============================================================================

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Config (override via env or edit here) ───────────────────────────────────
RECON_SCRIPT="${RECON_SCRIPT:-$(dirname "$0")/recon.sh}"
INSTALL_SCRIPT="${INSTALL_SCRIPT:-$(dirname "$0")/install_tools.sh}"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
TARGETS_FILE="${TARGETS_FILE:-}"
TARGET=""
DRY_RUN=false
INSTALL_CRON=false
STAGGER_SECS="${STAGGER_SECS:-300}"   # 5min between targets
MAX_PARALLEL="${MAX_PARALLEL:-2}"     # max concurrent scans

# ─── Notification config ──────────────────────────────────────────────────────
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
NOTIFY_EMAIL="${NOTIFY_EMAIL:-}"
# Minimum severity to alert on: critical | high | medium | all
ALERT_MIN_SEVERITY="${ALERT_MIN_SEVERITY:-high}"

# ─── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)   TARGET="$2"; shift 2 ;;
        -f|--file)     TARGETS_FILE="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=true; shift ;;
        --install-cron) INSTALL_CRON=true; shift ;;
        --slack)       SLACK_WEBHOOK="$2"; shift 2 ;;
        --discord)     DISCORD_WEBHOOK="$2"; shift 2 ;;
        --email)       NOTIFY_EMAIL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-t domain] [-f targets.txt] [--dry-run] [--install-cron]"
            echo "       [--slack WEBHOOK] [--discord WEBHOOK] [--email EMAIL]"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ─── Dirs & Logging ───────────────────────────────────────────────────────────
mkdir -p "$BASE_DIR/logs"
MONITOR_LOG="$BASE_DIR/logs/monitor_$(date +%Y%m%d).log"

log()  { echo -e "${CYAN}[*]${RESET} $(date +'%H:%M:%S') $*" | tee -a "$MONITOR_LOG"; }
ok()   { echo -e "${GREEN}[+]${RESET} $(date +'%H:%M:%S') $*" | tee -a "$MONITOR_LOG"; }
warn() { echo -e "${YELLOW}[!]${RESET} $(date +'%H:%M:%S') $*" | tee -a "$MONITOR_LOG"; }
err()  { echo -e "${RED}[-]${RESET} $(date +'%H:%M:%S') $*" | tee -a "$MONITOR_LOG"; }
step() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$MONITOR_LOG"
    echo -e "${BOLD}  $*${RESET}" | tee -a "$MONITOR_LOG"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$MONITOR_LOG"
}

# ─── Banner ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${GREEN}"
echo "  ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗"
echo "  ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗"
echo "  ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝"
echo "  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗"
echo "  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║"
echo "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
echo -e "${RESET}"

# ─── Pre-flight: tool installer ───────────────────────────────────────────────
preflight_install() {
    step "Pre-flight Tool Check"
    if [[ ! -f "$INSTALL_SCRIPT" ]]; then
        warn "install_tools.sh not found at $INSTALL_SCRIPT — skipping auto-install"
        return
    fi

    log "Running tool checker..."
    if bash "$INSTALL_SCRIPT" --check-only 2>/dev/null; then
        ok "All tools present — skipping install"
    else
        log "Missing tools detected — running installer..."
        bash "$INSTALL_SCRIPT" --force 2>&1 | tee -a "$MONITOR_LOG"
        ok "Tool install complete"
    fi

    # Reload PATH for go binaries
    export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"
}

# ─── Cron installer ──────────────────────────────────────────────────────────
install_cron() {
    local script_path
    script_path="$(realpath "$0")"

    if [[ -z "$TARGET" && -z "$TARGETS_FILE" ]]; then
        err "Provide -t <domain> or -f <file> to set up cron"
        exit 1
    fi

    local cron_args=""
    [[ -n "$TARGET" ]] && cron_args="-t $TARGET"
    [[ -n "$TARGETS_FILE" ]] && cron_args="-f $TARGETS_FILE"
    [[ -n "$SLACK_WEBHOOK" ]]   && cron_args+=" --slack '$SLACK_WEBHOOK'"
    [[ -n "$DISCORD_WEBHOOK" ]] && cron_args+=" --discord '$DISCORD_WEBHOOK'"
    [[ -n "$NOTIFY_EMAIL" ]]    && cron_args+=" --email '$NOTIFY_EMAIL'"

    # Run at 2am daily
    local cron_line="0 2 * * * bash $script_path $cron_args >> $BASE_DIR/logs/cron.log 2>&1"

    echo ""
    echo -e "${BOLD}Cron entry to add:${RESET}"
    echo ""
    echo "  $cron_line"
    echo ""
    read -rp "$(echo -e "${YELLOW}Add to crontab now? [y/N]:${RESET} ")" confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
        ok "Cron job installed — runs daily at 2am"
        crontab -l | grep -v "^#" | grep "$script_path"
    else
        log "Not added. You can add it manually with: crontab -e"
    fi
    exit 0
}

# ─── Notification functions ───────────────────────────────────────────────────

# Escape string for JSON
json_escape() {
    python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" <<< "$1" | tr -d '"'
}

send_slack() {
    local message="$1"
    [[ -z "$SLACK_WEBHOOK" ]] && return 0
    local escaped
    escaped=$(json_escape "$message")
    curl -s -X POST "$SLACK_WEBHOOK" \
        -H 'Content-type: application/json' \
        -d "{\"text\": \"$escaped\"}" \
        >> "$MONITOR_LOG" 2>&1 && ok "Slack notification sent" || warn "Slack notification failed"
}

send_discord() {
    local message="$1"
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0
    # Discord has 2000 char limit — truncate if needed
    local escaped
    escaped=$(json_escape "${message:0:1900}")
    curl -s -X POST "$DISCORD_WEBHOOK" \
        -H 'Content-type: application/json' \
        -d "{\"content\": \"$escaped\"}" \
        >> "$MONITOR_LOG" 2>&1 && ok "Discord notification sent" || warn "Discord notification failed"
}

send_email() {
    local subject="$1" body="$2"
    [[ -z "$NOTIFY_EMAIL" ]] && return 0
    if command -v mail &>/dev/null; then
        echo "$body" | mail -s "$subject" "$NOTIFY_EMAIL" && \
            ok "Email sent to $NOTIFY_EMAIL" || warn "Email send failed"
    elif command -v sendmail &>/dev/null; then
        printf "Subject: %s\n\n%s" "$subject" "$body" | sendmail "$NOTIFY_EMAIL" && \
            ok "Email sent via sendmail" || warn "sendmail failed"
    else
        warn "No mail utility found — skipping email notification"
    fi
}

notify_all() {
    local subject="$1" body="$2"
    send_slack "$subject\n\n$body"
    send_discord "$subject\n\n$body"
    send_email "$subject" "$body"
}

# ─── Diff Engine ─────────────────────────────────────────────────────────────

count_lines() { [[ -f "$1" ]] && grep -c . "$1" 2>/dev/null || echo 0; }

diff_file() {
    local label="$1" prev_file="$2" new_file="$3"
    local added=() removed=()

    [[ ! -f "$new_file" ]] && return 0

    if [[ -f "$prev_file" ]]; then
        mapfile -t added  < <(comm -23 <(sort "$new_file") <(sort "$prev_file") 2>/dev/null || true)
        mapfile -t removed < <(comm -13 <(sort "$new_file") <(sort "$prev_file") 2>/dev/null || true)
    else
        mapfile -t added < <(cat "$new_file" 2>/dev/null || true)
    fi

    local result=""
    if [[ ${#added[@]} -gt 0 ]]; then
        result+="📌 NEW $label (${#added[@]}):\n"
        for item in "${added[@]:0:20}"; do
            result+="  + $item\n"
        done
        [[ ${#added[@]} -gt 20 ]] && result+="  ... and $((${#added[@]} - 20)) more\n"
    fi
    if [[ ${#removed[@]} -gt 0 ]]; then
        result+="🗑 GONE $label (${#removed[@]}):\n"
        for item in "${removed[@]:0:10}"; do
            result+="  - $item\n"
        done
    fi

    echo -e "$result"
}

filter_by_severity() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    case "$ALERT_MIN_SEVERITY" in
        critical) grep -iE "^\[critical\]" "$file" 2>/dev/null || true ;;
        high)     grep -iE "^\[critical\]|^\[high\]" "$file" 2>/dev/null || true ;;
        medium)   grep -iE "^\[critical\]|^\[high\]|^\[medium\]" "$file" 2>/dev/null || true ;;
        *)        cat "$file" ;;
    esac
}

run_diff() {
    local domain="$1" new_run="$2"
    local domain_dir="$BASE_DIR/$domain"
    local latest_link="$domain_dir/latest"
    local diff_report=""
    local has_findings=false

    step "Diffing: $domain"

    if [[ ! -L "$latest_link" && ! -d "$latest_link" ]]; then
        log "No previous run found for $domain — this is the baseline run"
        ln -sfn "$new_run" "$latest_link"
        return 0
    fi

    local prev_run
    prev_run=$(readlink -f "$latest_link")

    if [[ "$prev_run" == "$new_run" ]]; then
        warn "Previous and new run are the same directory — skipping diff"
        return 0
    fi

    log "Comparing:"
    log "  Previous: $prev_run"
    log "  New:      $new_run"

    diff_report+="🔍 *Recon Diff — $domain*\n"
    diff_report+="🕐 $(date)\n\n"

    # ── Subdomains ──
    local sub_diff
    sub_diff=$(diff_file "SUBDOMAINS" \
        "$prev_run/subdomains/all_subs.txt" \
        "$new_run/subdomains/all_subs.txt")
    if [[ -n "$sub_diff" ]]; then
        diff_report+="🌐 *Subdomains*\n$sub_diff\n"
        has_findings=true
    fi

    # ── Live hosts ──
    local live_diff
    live_diff=$(diff_file "LIVE HOSTS" \
        "$prev_run/live/urls.txt" \
        "$new_run/live/urls.txt")
    if [[ -n "$live_diff" ]]; then
        diff_report+="🖥 *Live Hosts*\n$live_diff\n"
        has_findings=true
    fi

    # ── Nuclei findings ──
    local vuln_diff=""
    for sev in critical high medium; do
        local prev_vuln="$prev_run/vulns/nuclei_${sev}.txt"
        local new_vuln="$new_run/vulns/nuclei_${sev}.txt"
        [[ ! -f "$new_vuln" ]] && continue

        local new_only
        if [[ -f "$prev_vuln" ]]; then
            new_only=$(comm -23 <(sort "$new_vuln") <(sort "$prev_vuln") 2>/dev/null || true)
        else
            new_only=$(cat "$new_vuln" 2>/dev/null || true)
        fi

        if [[ -n "$new_only" ]]; then
            local emoji="⚠️"
            [[ "$sev" == "critical" ]] && emoji="🚨"
            [[ "$sev" == "high" ]] && emoji="🔴"
            vuln_diff+="$emoji *New $sev nuclei findings:*\n$new_only\n\n"
            has_findings=true
        fi
    done
    [[ -n "$vuln_diff" ]] && diff_report+="🎯 *Vulnerabilities*\n$vuln_diff"

    # ── XSS ──
    if [[ -f "$new_run/vulns/xss_dalfox.txt" ]] && \
       [[ "$(count_lines "$new_run/vulns/xss_dalfox.txt")" -gt 0 ]]; then
        local xss_new
        if [[ -f "$prev_run/vulns/xss_dalfox.txt" ]]; then
            xss_new=$(comm -23 \
                <(sort "$new_run/vulns/xss_dalfox.txt") \
                <(sort "$prev_run/vulns/xss_dalfox.txt") 2>/dev/null || true)
        else
            xss_new=$(cat "$new_run/vulns/xss_dalfox.txt")
        fi
        if [[ -n "$xss_new" ]]; then
            diff_report+="💉 *New XSS findings:*\n$xss_new\n\n"
            has_findings=true
        fi
    fi

    # ── Open Redirects ──
    if [[ -f "$new_run/vulns/open_redirects.txt" ]] && \
       [[ "$(count_lines "$new_run/vulns/open_redirects.txt")" -gt 0 ]]; then
        local redir_new
        if [[ -f "$prev_run/vulns/open_redirects.txt" ]]; then
            redir_new=$(comm -23 \
                <(sort "$new_run/vulns/open_redirects.txt") \
                <(sort "$prev_run/vulns/open_redirects.txt") 2>/dev/null || true)
        else
            redir_new=$(cat "$new_run/vulns/open_redirects.txt")
        fi
        if [[ -n "$redir_new" ]]; then
            diff_report+="↩️ *New Open Redirects:*\n$redir_new\n\n"
            has_findings=true
        fi
    fi

    # ── Subdomain Takeovers ──
    if [[ -f "$new_run/vulns/takeovers.txt" ]] && \
       [[ "$(count_lines "$new_run/vulns/takeovers.txt")" -gt 0 ]]; then
        local takeover_new
        if [[ -f "$prev_run/vulns/takeovers.txt" ]]; then
            takeover_new=$(comm -23 \
                <(sort "$new_run/vulns/takeovers.txt") \
                <(sort "$prev_run/vulns/takeovers.txt") 2>/dev/null || true)
        else
            takeover_new=$(cat "$new_run/vulns/takeovers.txt")
        fi
        if [[ -n "$takeover_new" ]]; then
            diff_report+="💀 *NEW SUBDOMAIN TAKEOVERS:*\n$takeover_new\n\n"
            has_findings=true
        fi
    fi

    # ── Secrets ──
    if [[ -f "$new_run/secrets/regex_secrets.txt" ]] && \
       [[ "$(count_lines "$new_run/secrets/regex_secrets.txt")" -gt 0 ]]; then
        local secrets_new
        if [[ -f "$prev_run/secrets/regex_secrets.txt" ]]; then
            secrets_new=$(comm -23 \
                <(sort "$new_run/secrets/regex_secrets.txt") \
                <(sort "$prev_run/secrets/regex_secrets.txt") 2>/dev/null || true)
        else
            secrets_new=$(cat "$new_run/secrets/regex_secrets.txt")
        fi
        if [[ -n "$secrets_new" ]]; then
            diff_report+="🔑 *New Potential Secrets:*\n${secrets_new:0:500}\n\n"
            has_findings=true
        fi
    fi

    # ── Stats summary ──
    diff_report+="📊 *Stats*\n"
    diff_report+="  Subdomains : $(count_lines "$new_run/subdomains/all_subs.txt")\n"
    diff_report+="  Live hosts : $(count_lines "$new_run/live/urls.txt")\n"
    diff_report+="  Total URLs : $(count_lines "$new_run/web/all_urls.txt")\n"
    diff_report+="  Report     : $new_run/SUMMARY.md\n"

    # Save diff report
    echo -e "$diff_report" > "$new_run/DIFF_REPORT.txt"
    ok "Diff report saved → $new_run/DIFF_REPORT.txt"

    # ── Notify ──
    if [[ "$has_findings" == true ]]; then
        ok "New findings detected — sending notifications"
        notify_all "🎯 Recon Alert: $domain" "$diff_report"
    else
        log "No new findings vs previous run for $domain"
        send_slack "✅ Recon complete for $domain — no new findings ($(date))"
    fi

    # Update latest symlink
    ln -sfn "$new_run" "$latest_link"
    ok "Updated latest → $latest_link"
}

# ─── Single Target Scan ───────────────────────────────────────────────────────
scan_target() {
    local domain="$1"
    local domain_dir="$BASE_DIR/$domain"
    mkdir -p "$domain_dir"

    step "Starting scan: $domain"

    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would run: $RECON_SCRIPT $domain $domain_dir"
        return 0
    fi

    if [[ ! -f "$RECON_SCRIPT" ]]; then
        err "recon.sh not found at $RECON_SCRIPT"
        err "Set RECON_SCRIPT env var or place recon.sh in the same directory"
        exit 1
    fi

    local start_time
    start_time=$(date +%s)

    # Run the recon — capture the output dir from its timestamped folder
    bash "$RECON_SCRIPT" "$domain" "$domain_dir" 2>&1 | tee -a "$MONITOR_LOG"

    # Find the run that was just created (most recent timestamped dir)
    local new_run
    new_run=$(find "$domain_dir" -maxdepth 1 -mindepth 1 -type d \
        -name "[0-9]*" | sort | tail -1)

    if [[ -z "$new_run" ]]; then
        err "Could not find output directory for $domain"
        return 1
    fi

    local elapsed=$(( $(date +%s) - start_time ))
    ok "Scan complete: $domain in $((elapsed/60))m $((elapsed%60))s"

    run_diff "$domain" "$new_run"
}

# ─── Multi-target Runner ─────────────────────────────────────────────────────
scan_all_targets() {
    local targets=()

    if [[ -n "$TARGET" ]]; then
        targets+=("$TARGET")
    fi

    if [[ -n "$TARGETS_FILE" ]]; then
        if [[ ! -f "$TARGETS_FILE" ]]; then
            err "Targets file not found: $TARGETS_FILE"
            exit 1
        fi
        while IFS= read -r line; do
            # Skip empty lines and comments
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            targets+=("$line")
        done < "$TARGETS_FILE"
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        err "No targets specified. Use -t <domain> or -f <file>"
        exit 1
    fi

    log "Targets to scan: ${#targets[@]}"
    for t in "${targets[@]}"; do log "  → $t"; done
    echo ""

    local active_jobs=0
    for domain in "${targets[@]}"; do
        # Respect parallelism limit
        while (( active_jobs >= MAX_PARALLEL )); do
            wait -n 2>/dev/null || wait
            (( active_jobs-- ))
        done

        log "Launching scan for $domain (job $((active_jobs+1))/$MAX_PARALLEL max)"
        scan_target "$domain" &
        (( active_jobs++ ))

        # Stagger starts to avoid thundering herd
        if [[ ${#targets[@]} -gt 1 ]]; then
            log "Staggering next scan by ${STAGGER_SECS}s..."
            sleep "$STAGGER_SECS"
        fi
    done

    # Wait for all background jobs
    wait
    ok "All scans complete"
}

# ─── Cron install shortcut ────────────────────────────────────────────────────
[[ "$INSTALL_CRON" == true ]] && install_cron

# ─── Run pre-flight tool check ────────────────────────────────────────────────
preflight_install

# ─── Main ─────────────────────────────────────────────────────────────────────
START=$(date +%s)
log "Monitor run started at $(date)"

if [[ -n "$SLACK_WEBHOOK" || -n "$DISCORD_WEBHOOK" || -n "$NOTIFY_EMAIL" ]]; then
    ok "Notifications configured"
    [[ -n "$SLACK_WEBHOOK" ]]   && log "  → Slack"
    [[ -n "$DISCORD_WEBHOOK" ]] && log "  → Discord"
    [[ -n "$NOTIFY_EMAIL" ]]    && log "  → Email: $NOTIFY_EMAIL"
else
    warn "No notification webhooks configured — findings will be saved to disk only"
    warn "Set SLACK_WEBHOOK, DISCORD_WEBHOOK, or NOTIFY_EMAIL env vars"
fi

scan_all_targets

ELAPSED=$(( $(date +%s) - START ))
ok "Monitor finished in $((ELAPSED/3600))h $(( (ELAPSED%3600)/60 ))m"
echo ""
echo -e "${BOLD}${GREEN}All outputs: $BASE_DIR${RESET}"
echo -e "${BOLD}${GREEN}Monitor log: $MONITOR_LOG${RESET}"
echo ""
