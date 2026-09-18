#!/usr/bin/env bash
# =======================================================
#  Anubis Installer — Linux Distributions
#  Instant standalone binary download & installation
#  Usage: curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
# =======================================================
set -euo pipefail

REPO="SepJs/anubis"
INSTALL_DIR="/usr/local/bin"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# Verify Linux distribution
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    die "Anubis is tailored exclusively for Linux distributions. Detected OS: $OS"
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *)             die "Unsupported Linux architecture: $ARCH (supported: amd64, arm64)" ;;
esac

info "Target platform: linux/${ARCH_NAME}"

# Setup destination directory
SUDO=""
if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi
fi

# 1. Download precompiled standalone binary (Fast, zero-dependency)
install_from_release() {
    command -v curl >/dev/null 2>&1 || return 1
    info "Fetching latest standalone Linux binary from GitHub Releases..."
    local base="https://github.com/${REPO}/releases/latest"
    local tag
    tag=$(curl -sIL -o /dev/null -w '%{url_effective}' "$base" 2>/dev/null | grep -o 'tag/[^/]*$' | head -n1 | cut -d/ -f2) || return 1
    [ -n "$tag" ] || return 1

    local clean_tag="${tag#v}"
    # Match release naming conventions
    local url="https://github.com/${REPO}/releases/download/${tag}/anubis_${clean_tag}_linux_${ARCH_NAME}"
    local tmp
    tmp=$(mktemp -d)
    
    if curl -fsSL "$url" -o "$tmp/anubis" 2>/dev/null; then
        chmod +x "$tmp/anubis"
        $SUDO mv "$tmp/anubis" "$INSTALL_DIR/anubis"
        rm -rf "$tmp"
        return 0
    fi
    rm -rf "$tmp"
    return 1
}

# 2. Local/Source fallback if Go compiler is available
install_from_source() {
    command -v go >/dev/null 2>&1 || return 1
    info "Compiling zero-CGO static binary from source..."
    local tmp
    tmp=$(mktemp -d)
    if [ -f "./cmd/anubis/main.go" ]; then
        CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$tmp/anubis" ./cmd/anubis || return 1
    else
        git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/src" 2>/dev/null || return 1
        ( cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$tmp/anubis" ./cmd/anubis ) || return 1
    fi
    chmod +x "$tmp/anubis"
    $SUDO mv "$tmp/anubis" "$INSTALL_DIR/anubis"
    rm -rf "$tmp"
    return 0
}

# Run installation
install_from_release || install_from_source || die "Failed to install Anubis binary."

ok "Anubis successfully installed to $INSTALL_DIR/anubis"

if ! command -v anubis >/dev/null 2>&1; then
    warn "$INSTALL_DIR is not currently in your system PATH."
    echo "    Add this to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\$PATH:$INSTALL_DIR"
fi

echo ""
info "Run directly from your terminal:"
echo "    anubis --help"
echo "    anubis -t https://example.com -l 1"
