#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
#  Anubis installer — Linux & macOS
#  Builds the SepJs/anubis security scanner from source
#  (fallback to a release asset if one exists).
#  Usage:  curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
# ═══════════════════════════════════════════════════════
set -euo pipefail

REPO="SepJs/anubis"
INSTALL_DIR="/usr/local/bin"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
die()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── detect OS/arch (only used for the release-asset branch) ──
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Linux*)  OS_NAME="linux" ;;
    Darwin*) OS_NAME="darwin" ;;
    *)       die "Unsupported OS: $OS — use install.ps1 on Windows" ;;
esac
case "$ARCH" in
    x86_64|amd64)  ARCH_NAME="amd64" ;;
    arm64|aarch64) ARCH_NAME="arm64" ;;
    armv7l|armv6l) ARCH_NAME="armv6" ;;
    i386|i686)     ARCH_NAME="386" ;;
    *)             die "Unsupported architecture: $ARCH" ;;
esac
info "Detected: ${OS_NAME}/${ARCH_NAME}"

# ── sudo / fallback dir ──
SUDO=""
if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"; warn "Write access to $INSTALL_DIR requires sudo"
    else
        INSTALL_DIR="$HOME/.local/bin"; mkdir -p "$INSTALL_DIR"
        warn "No sudo — installing to $INSTALL_DIR (make sure it's in PATH)"
    fi
fi

# ── build from SepJs/anubis source ──
install_from_source() {
    command -v go >/dev/null 2>&1 || return 1
    local go_ver; go_ver=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | tr -d 'go')
    [ -n "$go_ver" ] || return 1
    info "Building from source (go${go_ver}) ..."
    local tmp; tmp=$(mktemp -d)
    git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/src" 2>/dev/null || return 1
    ( cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$tmp/anubis" ./cmd/anubis ) || return 1
    $SUDO mv "$tmp/anubis" "$INSTALL_DIR/anubis"
}

# ── fallback: try a release asset (only if we ever publish one) ──
install_from_release() {
    command -v curl >/dev/null 2>&1 || return 1
    local base="https://github.com/${REPO}/releases/latest"
    local tag url
    tag=$(curl -sIL -o /dev/null -w '%{url_effective}' "$base" 2>/dev/null | grep -o 'tag/[^/]*$' | head -n1 | cut -d/ -f2) || return 1
    [ -n "$tag" ] || return 1
    local asset="anubis_${tag#v}_${OS_NAME}_${ARCH_NAME}"
    url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
    info "Downloading release asset: ${asset}"
    local tmp; tmp=$(mktemp -d)
    curl -fsSL "$url" -o "$tmp/anubis" 2>/dev/null || return 1
    chmod +x "$tmp/anubis"
    $SUDO mv "$tmp/anubis" "$INSTALL_DIR/anubis"
}

# ── main ──
install_from_source || install_from_release || die "Installation failed — need Go ≥1.21 (or a published release asset)"

if ! command -v anubis >/dev/null 2>&1; then
    warn "Installed but $INSTALL_DIR is not in your PATH."
    echo "    Add to your shell profile:"
    echo "    export PATH=\$PATH:$INSTALL_DIR"
    exit 0
fi

ok "Installed → $INSTALL_DIR/anubis"
echo ""
info "Try it:"
echo "    anubis -t https://example.com -l 1"
