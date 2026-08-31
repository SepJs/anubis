#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
#  Anubis installer — Linux & macOS
#  Detects OS/arch, builds (or downloads) and installs.
#  Usage:  curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
# ═══════════════════════════════════════════════════════
set -euo pipefail

REPO="SepJs/anubis"
VERSION="${ANUBIS_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
die()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

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

SUDO=""
if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        warn "Write access to $INSTALL_DIR requires sudo"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        warn "No sudo — installing to $INSTALL_DIR (make sure it's in PATH)"
    fi
fi

try_release_install() {
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || return 1

    local base="https://github.com/${REPO}"
    if [ "$VERSION" = "latest" ]; then
        # resolve latest release tag
        TAG=$(curl -sIL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null | grep -o 'tag/[^/]*$' | cut -d/ -f2) || return 1
        [ -n "$TAG" ] || return 1
    else
        TAG="$VERSION"
    fi

    local asset="anubis_${TAG#v}_${OS_NAME}_${ARCH_NAME}"
    local url="https://github.com/${REPO}/releases/download/${TAG}/${asset}"

    info "Downloading release asset: ${asset}"
    local tmp; tmp=$(mktemp -d)
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp/anubis" 2>/dev/null || return 1
    else
        wget -q "$url" -O "$tmp/anubis" 2>/dev/null || return 1
    fi

    chmod +x "$tmp/anubis"
    $SUDO mv "$tmp/anubis" "$INSTALL_DIR/anubis"
    return 0
}

try_source_install() {
    command -v go >/dev/null 2>&1 || return 1

    local go_min="1.21"
    local go_ver
    go_ver=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | tr -d 'go')
    [ -n "$go_ver" ] || return 1

    info "Building from source (go${go_ver})..."
    local tmp; tmp=$(mktemp -d)

    git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/anubis" 2>/dev/null || return 1
    cd "$tmp/anubis"

    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$tmp/anubis-bin" ./cmd/anubis || return 1

    $SUDO mv "$tmp/anubis-bin" "$INSTALL_DIR/anubis"
    return 0
}

if try_release_install; then
    ok "Installed from GitHub release → $INSTALL_DIR/anubis"
elif try_source_install; then
    ok "Built and installed from source → $INSTALL_DIR/anubis"
else
    die "Installation failed — need either internet access to GitHub releases, or Go ${go_min}+ installed"
fi

if command -v anubis >/dev/null 2>&1; then
    ok "anubis is ready: $(anubis --version 2>/dev/null | head -n1 || echo "$INSTALL_DIR/anubis")"
    echo ""
    info "Try it:"
    echo "    anubis -t https://example.com -l 1"
else
    warn "Installed but $INSTALL_DIR is not in PATH"
    echo "    Add this to your shell profile:"
    echo "    export PATH=\$PATH:$INSTALL_DIR"
fi
