#!/usr/bin/env bash
# Download and install sir pre-built binaries from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash -s -- v0.0.2
#
# Installs sir and mister-core to ~/.local/bin. Pass a version tag as
# the first argument to pin a specific release; defaults to latest.
#
# Security: the downloaded tarball is verified against the SHA-256
# checksum published in the release's checksums.txt before installation.
# For full cryptographic verification (cosign signatures, SLSA provenance),
# see scripts/verify-release.sh.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# --- Version resolution ---
VERSION="${1:-latest}"
REPO="somoore/sir"

if [ "$VERSION" = "latest" ]; then
    info "Resolving latest release..."
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

# --- Download ---
TARBALL="sir_${VERSION}_${PLATFORM}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
INSTALL_DIR="$HOME/.local/bin"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${TARBALL}..."
curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}" \
    || error "Download failed. Check that ${VERSION} exists at https://github.com/${REPO}/releases"

# --- Checksum verification ---
info "Verifying checksum..."
curl -fsSL "${BASE_URL}/checksums.txt" -o "${TMPDIR}/checksums.txt" \
    || error "Could not download checksums.txt — cannot verify integrity."

ACTUAL_SHA256=$(sha256_of "${TMPDIR}/${TARBALL}")
EXPECTED_SHA256=$(grep "${TARBALL}" "${TMPDIR}/checksums.txt" | awk '{print $1}')

if [ -z "$EXPECTED_SHA256" ]; then
    error "Tarball ${TARBALL} not found in checksums.txt — cannot verify integrity."
fi

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    error "Checksum mismatch!
    Expected: ${EXPECTED_SHA256}
    Actual:   ${ACTUAL_SHA256}
    The downloaded archive may have been tampered with. Do not install."
fi
info "Checksum verified: ${ACTUAL_SHA256}"

# --- Extract and install ---
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
echo ""
echo "For full cryptographic verification (cosign signatures):"
echo "  https://github.com/${REPO}/blob/main/scripts/verify-release.sh"
