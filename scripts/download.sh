#!/usr/bin/env bash
# Download and install sir pre-built binaries from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash -s -- v0.0.2
#
# Installs sir and mister-core to ~/.local/bin. Pass a version tag as
# the first argument to pin a specific release; defaults to latest.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Version resolution ---
VERSION="${1:-latest}"
REPO="somoore/sir"

if [ "$VERSION" = "latest" ]; then
    info "Resolving latest release..."
    # Use the releases endpoint and extract the first tag_name.
    # The redirect from /releases/latest doesn't work for pre-releases,
    # so we query the list and take the first entry.
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=1" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || error "Could not determine latest release."
fi
info "Version: ${VERSION}"

# --- Platform detection ---
OS=$(uname -s)
ARCH=$(uname -m)
case "${OS}-${ARCH}" in
    Darwin-arm64)   PLATFORM="darwin_arm64" ;;
    Linux-x86_64)   PLATFORM="linux_amd64"  ;;
    Linux-aarch64)  PLATFORM="linux_arm64"  ;;
    *)              error "Unsupported platform: ${OS}-${ARCH}. sir supports macOS (Apple Silicon) and Linux (amd64, arm64)." ;;
esac
info "Platform: ${PLATFORM}"

# --- Download and install ---
TARBALL="sir_${VERSION}_${PLATFORM}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
INSTALL_DIR="$HOME/.local/bin"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${URL}..."
curl -fsSL "$URL" -o "${TMPDIR}/${TARBALL}" || error "Download failed. Check that ${VERSION} exists at https://github.com/${REPO}/releases"

info "Extracting..."
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

[ -f "${TMPDIR}/sir" ] || error "Archive missing 'sir' binary."
[ -f "${TMPDIR}/mister-core" ] || error "Archive missing 'mister-core' binary."

mkdir -p "$INSTALL_DIR"
install -m 750 "${TMPDIR}/sir" "${TMPDIR}/mister-core" "$INSTALL_DIR/"

info "Installed to ${INSTALL_DIR}/"

# --- PATH setup ---
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    SHELL_PROFILE=""
    [ -f "$HOME/.zshrc" ] && SHELL_PROFILE="$HOME/.zshrc"
    [ -z "$SHELL_PROFILE" ] && [ -f "$HOME/.bashrc" ] && SHELL_PROFILE="$HOME/.bashrc"
    [ -z "$SHELL_PROFILE" ] && [ -f "$HOME/.bash_profile" ] && SHELL_PROFILE="$HOME/.bash_profile"

    if [ -n "$SHELL_PROFILE" ]; then
        if ! grep -q '/.local/bin' "$SHELL_PROFILE" 2>/dev/null; then
            echo '' >> "$SHELL_PROFILE"
            echo '# sir - Sandbox in Reverse' >> "$SHELL_PROFILE"
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_PROFILE"
            info "Added ~/.local/bin to PATH in ${SHELL_PROFILE}"
        fi
    else
        echo ""
        echo "    Could not detect shell profile. Add this manually:"
        echo '    export PATH="$HOME/.local/bin:$PATH"'
        echo ""
    fi
    export PATH="${INSTALL_DIR}:$PATH"
fi

info "$(sir version)"
echo ""
echo "Next: cd into a project and run 'sir install' to set up agent hooks."
