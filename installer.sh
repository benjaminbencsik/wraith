#!/usr/bin/env bash
# =============================================================================
# install_tools.sh — Bug Bounty Tool Installer
# Detects what's missing and installs only what's needed.
# Usage: ./install_tools.sh [--force] [--go-only] [--check-only]
# =============================================================================

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
TICK="${GREEN}✔${RESET}"; CROSS="${RED}✘${RESET}"; ARROW="${CYAN}→${RESET}"

# ─── Flags ───────────────────────────────────────────────────────────────────
FORCE=false
CHECK_ONLY=false
GO_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --force)      FORCE=true ;;
        --check-only) CHECK_ONLY=true ;;
        --go-only)    GO_ONLY=true ;;
    esac
done

# ─── Logging ─────────────────────────────────────────────────────────────────
INSTALL_LOG="$HOME/.recon_install.log"
log()    { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$INSTALL_LOG"; }
ok()     { echo -e "${TICK} $*" | tee -a "$INSTALL_LOG"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$INSTALL_LOG"; }
err()    { echo -e "${CROSS} ${RED}$*${RESET}" | tee -a "$INSTALL_LOG"; }
install_log() { echo -e "  ${ARROW} $*" | tee -a "$INSTALL_LOG"; }

echo "" | tee -a "$INSTALL_LOG"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}" | tee -a "$INSTALL_LOG"
echo -e "${BOLD}   Bug Bounty Tool Installer$(date +'  %Y-%m-%d %H:%M')${RESET}" | tee -a "$INSTALL_LOG"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}" | tee -a "$INSTALL_LOG"

# ─── OS Detection ────────────────────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
        echo "debian"
    elif grep -qi "fedora\|rhel\|centos\|amazon" /etc/os-release 2>/dev/null; then
        echo "rhel"
    elif grep -qi "arch" /etc/os-release 2>/dev/null; then
        echo "arch"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
log "Detected OS: $OS"

# ─── Go Setup ────────────────────────────────────────────────────────────────
GOPATH="${GOPATH:-$HOME/go}"
GOBIN="$GOPATH/bin"

ensure_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        ok "Go already installed: $GO_VER"
        return 0
    fi

    log "Go not found — installing..."
    local GO_VERSION="1.22.3"
    local ARCH
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64"

    local TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"

    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install go
        else
            err "Homebrew not found. Install from https://brew.sh then re-run."
            exit 1
        fi
    else
        install_log "Downloading Go $GO_VERSION..."
        curl -fsSL "https://go.dev/dl/$TARBALL" -o "/tmp/$TARBALL"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/$TARBALL"
        rm -f "/tmp/$TARBALL"

        # Add to PATH if not already there
        if ! grep -q "/usr/local/go/bin" "$HOME/.bashrc" 2>/dev/null; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
        fi
        if ! grep -q "/usr/local/go/bin" "$HOME/.profile" 2>/dev/null; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.profile"
        fi
        export PATH="$PATH:/usr/local/go/bin:$GOBIN"
    fi

    if command -v go &>/dev/null; then
        ok "Go installed: $(go version)"
    else
        err "Go installation failed. Please install manually: https://go.dev/dl/"
        exit 1
    fi
}

# Make sure GOBIN is in PATH for this session
export PATH="$PATH:/usr/local/go/bin:$GOBIN"

# ─── Package Manager Install ──────────────────────────────────────────────────
pkg_install() {
    local pkg="$1"
    install_log "Installing $pkg via package manager..."
    case "$OS" in
        macos)   brew install "$pkg" ;;
        debian)  sudo apt-get install -y "$pkg" ;;
        rhel)    sudo dnf install -y "$pkg" 2>/dev/null || sudo yum install -y "$pkg" ;;
        arch)    sudo pacman -S --noconfirm "$pkg" ;;
        *)       warn "Unknown OS — cannot auto-install $pkg via package manager" ;;
    esac
}

# ─── Tool Definitions ────────────────────────────────────────────────────────
# Each entry: "binary|install_type|install_command_or_go_path"
# Types: go, pkg, curl, pip

declare -A TOOL_TYPE
declare -A TOOL_INSTALL
declare -A TOOL_DESC

define_tool() {
    local bin="$1" type="$2" install="$3" desc="$4"
    TOOL_TYPE["$bin"]="$type"
    TOOL_INSTALL["$bin"]="$install"
    TOOL_DESC["$bin"]="$desc"
}

# Go tools
define_tool "subfinder"   "go"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"   "Subdomain enumeration"
define_tool "assetfinder" "go"   "github.com/tomnomnom/assetfinder@latest"                          "Subdomain/asset discovery"
define_tool "httpx"       "go"   "github.com/projectdiscovery/httpx/cmd/httpx@latest"               "HTTP probing"
define_tool "nuclei"      "go"   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"          "Vulnerability scanning"
define_tool "ffuf"        "go"   "github.com/ffuf/ffuf/v2@latest"                                   "Web fuzzing"
define_tool "gau"         "go"   "github.com/lc/gau/v2/cmd/gau@latest"                             "URL collection (wayback/ccrawl)"
define_tool "waybackurls" "go"   "github.com/tomnomnom/waybackurls@latest"                         "Wayback Machine URL fetcher"
define_tool "katana"      "go"   "github.com/projectdiscovery/katana/cmd/katana@latest"             "Active web crawler"
define_tool "dalfox"      "go"   "github.com/hahwul/dalfox/v2@latest"                              "XSS scanner"
define_tool "anew"        "go"   "github.com/tomnomnom/anew@latest"                                 "Append new unique lines"
define_tool "gowitness"   "go"   "github.com/sensepost/gowitness@latest"                           "Web screenshots"
define_tool "trufflehog"  "go"   "github.com/trufflesecurity/trufflehog/v3@latest"                 "Secret/credential scanner"

# Package manager tools
define_tool "nmap"        "pkg"  "nmap"     "Port/service scanner"
define_tool "jq"          "pkg"  "jq"       "JSON processor"
define_tool "curl"        "pkg"  "curl"     "HTTP client"
define_tool "git"         "pkg"  "git"      "Version control"
define_tool "python3"     "pkg"  "python3"  "Python runtime"

# curl-installed tools
define_tool "findomain"   "curl" "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-musl.zip|findomain" "Subdomain enumeration"

# pip tools
define_tool "sqlmap"      "pip"  "sqlmap"   "SQL injection scanner"

# ─── Check & Install ─────────────────────────────────────────────────────────
MISSING=()
INSTALLED=()
FAILED=()

check_tool() {
    local bin="$1"
    if command -v "$bin" &>/dev/null; then
        return 0
    fi
    # Also check GOBIN directly (PATH may not be updated yet in this session)
    if [[ -f "$GOBIN/$bin" ]]; then
        return 0
    fi
    return 1
}

install_tool() {
    local bin="$1"
    local type="${TOOL_TYPE[$bin]}"
    local install_val="${TOOL_INSTALL[$bin]}"

    install_log "Installing $bin (${TOOL_DESC[$bin]})..."

    case "$type" in
        go)
            go install -v "$install_val" 2>>"$INSTALL_LOG" && \
                ok "$bin installed via go install" || { err "Failed to install $bin"; return 1; }
            ;;

        pkg)
            if [[ "$OS" == "macos" ]] && ! command -v brew &>/dev/null; then
                warn "Homebrew not found — skipping $bin (install from https://brew.sh)"
                return 1
            fi
            pkg_install "$install_val" >> "$INSTALL_LOG" 2>&1 && \
                ok "$bin installed via package manager" || { err "Failed to install $bin"; return 1; }
            ;;

        curl)
            local url="${install_val%%|*}"
            local bin_name="${install_val##*|}"
            local tmp_dir
            tmp_dir=$(mktemp -d)

            install_log "Downloading $bin from $url..."
            if [[ "$url" == *.zip ]]; then
                curl -fsSL "$url" -o "$tmp_dir/${bin_name}.zip" 2>>"$INSTALL_LOG"
                unzip -o "$tmp_dir/${bin_name}.zip" -d "$tmp_dir" >> "$INSTALL_LOG" 2>&1
            else
                curl -fsSL "$url" -o "$tmp_dir/$bin_name" 2>>"$INSTALL_LOG"
            fi

            chmod +x "$tmp_dir/$bin_name"
            sudo mv "$tmp_dir/$bin_name" /usr/local/bin/ && \
                ok "$bin installed to /usr/local/bin/" || { err "Failed to install $bin"; rm -rf "$tmp_dir"; return 1; }
            rm -rf "$tmp_dir"
            ;;

        pip)
            if ! command -v pip3 &>/dev/null; then
                warn "pip3 not found — attempting to install python3-pip..."
                pkg_install "python3-pip" >> "$INSTALL_LOG" 2>&1 || { err "pip3 unavailable, skipping $bin"; return 1; }
            fi
            pip3 install "$install_val" --break-system-packages >> "$INSTALL_LOG" 2>&1 && \
                ok "$bin installed via pip3" || { err "Failed to install $bin"; return 1; }
            ;;

        *)
            err "Unknown install type '$type' for $bin"
            return 1
            ;;
    esac
}

# ─── Main Install Flow ────────────────────────────────────────────────────────

# Step 1: Scan what's missing
echo ""
log "Scanning for installed tools..."
echo ""

ALL_TOOLS=(subfinder assetfinder findomain httpx nmap nuclei ffuf gau \
           waybackurls katana dalfox anew gowitness trufflehog jq curl \
           git python3 sqlmap)

[[ "$GO_ONLY" == true ]] && ALL_TOOLS=(subfinder assetfinder httpx nuclei ffuf \
                                        gau waybackurls katana dalfox anew \
                                        gowitness trufflehog findomain)

printf "  %-20s %-12s %s\n" "TOOL" "STATUS" "DESCRIPTION"
printf "  %-20s %-12s %s\n" "────────────────────" "──────────" "───────────────────────────────"

for bin in "${ALL_TOOLS[@]}"; do
    if check_tool "$bin"; then
        printf "  ${TICK} %-18s ${GREEN}%-12s${RESET} %s\n" "$bin" "installed" "${TOOL_DESC[$bin]:-}"
        INSTALLED+=("$bin")
    else
        printf "  ${CROSS} %-18s ${RED}%-12s${RESET} %s\n" "$bin" "MISSING" "${TOOL_DESC[$bin]:-}"
        MISSING+=("$bin")
    fi
done

echo ""
log "Installed: ${#INSTALLED[@]} / $((${#INSTALLED[@]} + ${#MISSING[@]}))"

# Step 2: Nothing to do
if [[ ${#MISSING[@]} -eq 0 ]]; then
    ok "All tools are already installed. Nothing to do."
    exit 0
fi

# Step 3: Check-only mode
if [[ "$CHECK_ONLY" == true ]]; then
    warn "Missing tools: ${MISSING[*]}"
    warn "Run without --check-only to install them."
    exit 1
fi

# Step 4: Confirm
echo ""
warn "The following tools will be installed: ${MISSING[*]}"
if [[ "$FORCE" != true ]]; then
    read -rp "$(echo -e "${YELLOW}Proceed? [y/N]:${RESET} ")" confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }
fi

# Step 5: Ensure system deps first
echo ""
log "Ensuring system dependencies..."

if [[ "$OS" == "debian" ]]; then
    sudo apt-get update -qq >> "$INSTALL_LOG" 2>&1
    sudo apt-get install -y -qq curl wget unzip git python3 python3-pip \
        build-essential >> "$INSTALL_LOG" 2>&1
    ok "System deps ready (debian)"
elif [[ "$OS" == "rhel" ]]; then
    sudo dnf install -y curl wget unzip git python3 python3-pip \
        gcc >> "$INSTALL_LOG" 2>&1 || true
    ok "System deps ready (rhel)"
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Install from https://brew.sh"
    else
        brew update --quiet >> "$INSTALL_LOG" 2>&1 || true
        ok "Homebrew updated"
    fi
fi

# Step 6: Ensure Go (required for most tools)
needs_go=false
for bin in "${MISSING[@]}"; do
    [[ "${TOOL_TYPE[$bin]:-}" == "go" ]] && { needs_go=true; break; }
done

if [[ "$needs_go" == true ]]; then
    echo ""
    log "Go is required for several tools..."
    ensure_go
fi

# Step 7: Install missing tools
echo ""
log "Installing missing tools..."
echo ""

for bin in "${MISSING[@]}"; do
    echo -e "${BOLD}── Installing: $bin ──────────────────────────────────${RESET}" | tee -a "$INSTALL_LOG"
    if install_tool "$bin"; then
        INSTALLED+=("$bin")
    else
        FAILED+=("$bin")
        warn "Skipping $bin — will continue with remaining tools"
    fi
    echo ""
done

# Step 8: Update nuclei templates
if command -v nuclei &>/dev/null || [[ -f "$GOBIN/nuclei" ]]; then
    echo ""
    log "Updating nuclei templates..."
    "$GOBIN/nuclei" -update-templates -silent >> "$INSTALL_LOG" 2>&1 && \
        ok "Nuclei templates updated" || warn "Nuclei template update failed (non-fatal)"
fi

# Step 9: PATH reminder
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Install Complete${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""

if [[ ${#FAILED[@]} -gt 0 ]]; then
    warn "Failed to install: ${FAILED[*]}"
    warn "You may need to install these manually — check $INSTALL_LOG"
else
    ok "All tools installed successfully!"
fi

echo ""
echo -e "${YELLOW}Important:${RESET} If this is a fresh Go install, reload your shell or run:"
echo -e "  ${BOLD}source ~/.bashrc${RESET}   (or ~/.zshrc / ~/.profile)"
echo -e "  ${BOLD}export PATH=\$PATH:\$HOME/go/bin${RESET}"
echo ""
echo -e "Full install log: ${BOLD}$INSTALL_LOG${RESET}"
