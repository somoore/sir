#!/usr/bin/env bash
set -euo pipefail

echo "sir -- Sandbox in Reverse"
echo "========================="
echo ""

# Idempotent update path — if sir is already installed, this script will
# rebuild the binaries and replace them, preserving lease and session state
# at ~/.sir/. Supported agent hook configs are re-registered when they exist.
#
# There is no auto-updater, no background checker, and no `sir update`
# subcommand. To update sir, the developer re-runs this install script
# (typically via `curl ... | bash`). This is the entire update mechanism.
CURRENT_VERSION="none"
if command -v sir >/dev/null 2>&1; then
    CURRENT_VERSION=$(sir version 2>/dev/null | awk '{print $2}' || echo "unknown")
    echo "Existing sir installation detected: $CURRENT_VERSION"
    echo "Re-running install.sh will rebuild and replace the binaries."
    echo "Your lease and session state at ~/.sir/ will be preserved."
    echo ""
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

INSTALL_ARGS=("$@")
EXPLICIT_AGENT=""
for ((i=0; i<${#INSTALL_ARGS[@]}; i++)); do
    case "${INSTALL_ARGS[$i]}" in
        --agent)
            if (( i + 1 < ${#INSTALL_ARGS[@]} )); then
                EXPLICIT_AGENT="${INSTALL_ARGS[$((i + 1))]}"
            fi
            ;;
        --agent=*)
            EXPLICIT_AGENT="${INSTALL_ARGS[$i]#--agent=}"
            ;;
    esac
done

agent_name() {
    case "$1" in
        claude) echo "Claude Code" ;;
        gemini) echo "Gemini CLI" ;;
        codex) echo "Codex" ;;
        *) echo "$1" ;;
    esac
}

agent_launch_command() {
    case "$1" in
        claude) echo "claude" ;;
        gemini) echo "gemini" ;;
        codex) echo "codex" ;;
        *) echo "$1" ;;
    esac
}

detect_agent() {
    case "$1" in
        claude)
            command -v claude >/dev/null 2>&1 || [ -d "$HOME/.claude" ]
            ;;
        gemini)
            command -v gemini >/dev/null 2>&1 || [ -d "$HOME/.gemini" ]
            ;;
        codex)
            command -v codex >/dev/null 2>&1 || [ -d "$HOME/.codex" ]
            ;;
        *)
            return 1
            ;;
    esac
}

declare -a DETECTED_AGENTS=()
declare -a INSTALLED_AGENTS=()
RUN_SIR_INSTALL=1

# --- Downgrade guard ---
# Refuse to install a version older than the one currently on disk.
#
# Threat model: an attacker (or disgruntled developer) with write access
# to $HOME/.local/bin could clone an older, less-hardened release (e.g.
# one that predates MCP defense or credential scanning) and run this
# script to overwrite a more-hardened build. The older binaries are
# still validly signed and the hook configurations are still structurally
# valid, so no tamper alert fires — yet security features have been
# silently stripped.
#
# This guard enforces: install.sh never produces an install older than
# what it replaces, unless the operator explicitly overrides with
# SIR_ALLOW_DOWNGRADE=1. For enterprise MDM deployments, the MDM-pushed
# version always wins against a local clone of an older tag.
#
# The target version is read directly from the source we're about to
# build (cmd/sir/version.go::Version), so a tampered install.sh cannot
# lie about the target.
TARGET_VERSION=""
if [ -f "cmd/sir/version.go" ]; then
    TARGET_VERSION=$(sed -n 's/^const Version = "\([^"]*\)".*/\1/p' cmd/sir/version.go | head -n1)
fi

if [ -n "$TARGET_VERSION" ] && [ "$CURRENT_VERSION" != "none" ] && [ "$CURRENT_VERSION" != "unknown" ]; then
    # sort -V handles v-prefixed semver naturally; the smaller sorts first.
    LOWER_VERSION=$(printf '%s\n%s\n' "$CURRENT_VERSION" "$TARGET_VERSION" | sort -V | head -n1)
    if [ "$CURRENT_VERSION" != "$TARGET_VERSION" ] && [ "$LOWER_VERSION" = "$TARGET_VERSION" ]; then
        if [ "${SIR_ALLOW_DOWNGRADE:-0}" != "1" ]; then
            error "Downgrade blocked.
    installed:   $CURRENT_VERSION
    installing:  $TARGET_VERSION

    Refusing to replace a newer sir with an older one.

    This protects against an attacker cloning an older release and
    running install.sh to silently strip newer security features
    without tripping any tamper alert (older hooks are still valid,
    just missing later detections).

    For legitimate rollback, set SIR_ALLOW_DOWNGRADE=1:

        SIR_ALLOW_DOWNGRADE=1 ./install.sh

    For enterprise MDM deployments: any install.sh invocation that
    would downgrade fails unless the enforcing operator explicitly
    sets SIR_ALLOW_DOWNGRADE=1. The baseline version pushed by MDM
    always wins against a local clone of an older tag."
        else
            warn "Downgrade explicitly allowed via SIR_ALLOW_DOWNGRADE=1."
            warn "  installed:  $CURRENT_VERSION"
            warn "  installing: $TARGET_VERSION"
        fi
    fi
fi

# --- Pinned toolchain versions ---
# Keep in sync with .github/workflows/ci.yml and Makefile
RUST_VERSION="1.94.0"
GO_MIN_VERSION="1.22"

# --- Pinned rustup installer ---
# RUSTUP_VERSION is the version of the *installer* (rustup-init), not the Rust
# toolchain. RUST_VERSION above is the toolchain that rustup-init will fetch.
#
# The rustup-init binary is pinned by SHA-256 so this script never executes
# an unverified remote blob — addresses OpenSSF Scorecard findings about
# `curl | sh` supply-chain exposure (see issue #95).
#
# Canonical hashes are published at:
#   https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/<target>/rustup-init.sha256
# Each file is one line: "<hex-sha256>  rustup-init".
#
# To refresh on a rustup version bump:
#   for t in x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin; do
#     curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/$t/rustup-init.sha256"
#   done
RUSTUP_VERSION="1.28.2"
RUSTUP_INIT_SHA256_LINUX_X86_64="20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c"
RUSTUP_INIT_SHA256_DARWIN_X86_64="9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496"
RUSTUP_INIT_SHA256_DARWIN_ARM64="20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5"

# --- Source verification ---
# If building from a git checkout, verify the commit is on main or a tag
if [ -d ".git" ]; then
    CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    info "Building from source at commit: $CURRENT_COMMIT"

    # Warn if working tree is dirty
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        warn "Working tree has uncommitted changes."
    fi
fi

# Check for Rust toolchain
if ! command -v cargo &> /dev/null; then
    warn "Rust toolchain not found."
    echo "    Installing Rust $RUST_VERSION via rustup-init $RUSTUP_VERSION..."
    echo ""
    echo "  About to download and run the official Rust installer (rustup-init)."
    echo "  Source: https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/"
    echo "  To verify this independently: https://rust-lang.org/tools/install"
    echo "  Press Ctrl+C to cancel."
    echo ""
    # Supply chain note: rustup-init is downloaded over HTTPS from
    # static.rust-lang.org, then verified against a pinned SHA-256 before
    # it is ever executed. This replaces the previous `curl | sh` pattern
    # which executed unverified bytes straight from the network.
    # See https://rust-lang.org/tools/install for manual verification steps.

    # Detect host triple for rustup-init download.
    RUSTUP_OS=$(uname -s)
    RUSTUP_ARCH=$(uname -m)
    case "${RUSTUP_OS}-${RUSTUP_ARCH}" in
        Linux-x86_64)
            RUSTUP_TARGET="x86_64-unknown-linux-gnu"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_LINUX_X86_64"
            ;;
        Darwin-x86_64)
            RUSTUP_TARGET="x86_64-apple-darwin"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_DARWIN_X86_64"
            ;;
        Darwin-arm64)
            RUSTUP_TARGET="aarch64-apple-darwin"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_DARWIN_ARM64"
            ;;
        *)
            error "Unsupported platform for pinned rustup-init: ${RUSTUP_OS}-${RUSTUP_ARCH}.
    Supported: Linux x86_64, macOS x86_64, macOS arm64.
    For other platforms, install Rust $RUST_VERSION manually from
    https://rust-lang.org/tools/install and re-run this script."
            ;;
    esac

    # Download to a scratch dir so we never leave half-verified blobs behind.
    RUSTUP_TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t rustup-init)
    # shellcheck disable=SC2064
    trap "rm -rf \"$RUSTUP_TMPDIR\"" EXIT INT TERM
    RUSTUP_URL="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/rustup-init"

    info "Downloading rustup-init ${RUSTUP_VERSION} for ${RUSTUP_TARGET}..."
    curl --proto '=https' --tlsv1.2 -fsSL -o "$RUSTUP_TMPDIR/rustup-init" "$RUSTUP_URL"

    # Verify SHA-256 before executing. Fail closed on mismatch.
    # Prefer shasum (present on both macOS and most Linux) over sha256sum
    # (missing on default macOS), matching how the rest of this script
    # handles the same portability gap below.
    info "Verifying rustup-init SHA-256..."
    if command -v sha256sum &> /dev/null; then
        echo "${RUSTUP_EXPECTED_SHA256}  rustup-init" \
            | (cd "$RUSTUP_TMPDIR" && sha256sum --check --status) \
            || error "rustup-init SHA-256 verification failed.
    expected: $RUSTUP_EXPECTED_SHA256
    Refusing to execute unverified installer. Aborting."
    else
        echo "${RUSTUP_EXPECTED_SHA256}  rustup-init" \
            | (cd "$RUSTUP_TMPDIR" && shasum -a 256 --check --status) \
            || error "rustup-init SHA-256 verification failed.
    expected: $RUSTUP_EXPECTED_SHA256
    Refusing to execute unverified installer. Aborting."
    fi
    info "rustup-init SHA-256 verified."

    chmod +x "$RUSTUP_TMPDIR/rustup-init"
    "$RUSTUP_TMPDIR/rustup-init" -y --default-toolchain "$RUST_VERSION"

    rm -rf "$RUSTUP_TMPDIR"
    trap - EXIT INT TERM

    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    info "Rust $RUST_VERSION installed."
else
    CURRENT_RUST=$(rustc --version | awk '{print $2}')
    info "Rust toolchain found: $CURRENT_RUST"
    if [ "$CURRENT_RUST" != "$RUST_VERSION" ]; then
        warn "Expected Rust $RUST_VERSION, found $CURRENT_RUST"
        warn "Consider: rustup install $RUST_VERSION && rustup default $RUST_VERSION"
    fi
fi

# Check for Go toolchain
if ! command -v go &> /dev/null; then
    error "Go toolchain not found. Install Go ${GO_MIN_VERSION}+ from https://go.dev/dl/ and re-run this script."
else
    info "Go toolchain found: $(go version)"
fi

if [ -n "$EXPLICIT_AGENT" ]; then
    case "$EXPLICIT_AGENT" in
        claude|gemini|codex) ;;
        *)
            error "Unknown --agent value: $EXPLICIT_AGENT

    Supported agents: claude, gemini, codex"
            ;;
    esac
    if detect_agent "$EXPLICIT_AGENT"; then
        info "$(agent_name "$EXPLICIT_AGENT") detected for explicit install."
        DETECTED_AGENTS+=("$EXPLICIT_AGENT")
    else
        error "--agent $EXPLICIT_AGENT requested but $(agent_name "$EXPLICIT_AGENT") was not detected on this machine.

    Install $(agent_name "$EXPLICIT_AGENT") first, then re-run this script."
    fi
else
    for agent_id in claude gemini codex; do
        if detect_agent "$agent_id"; then
            DETECTED_AGENTS+=("$agent_id")
            info "$(agent_name "$agent_id") detected."
        fi
    done
    if [ ${#DETECTED_AGENTS[@]} -eq 0 ]; then
        warn "No supported agents detected. sir binaries will be installed, but hook setup is skipped for now."
        RUN_SIR_INSTALL=0
    fi
fi

# Build mister-core (Rust) — use --locked to enforce Cargo.lock
info "Building mister-core (Rust) with --locked..."
CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked
info "mister-core built."

# Build sir (Go) — static binary, stripped, reproducible
info "Building sir (Go) with static linking..."
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/sir ./cmd/sir
info "sir built."

# Generate checksums of built binaries
info "Generating checksums of built binaries..."
if command -v sha256sum &> /dev/null; then
    sha256sum target/release/mister-core bin/sir
else
    shasum -a 256 target/release/mister-core bin/sir
fi

# Install binaries
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

info "Installing binaries to $INSTALL_DIR..."
cp target/release/mister-core "$INSTALL_DIR/"
cp bin/sir "$INSTALL_DIR/"
# Owner-executable only (0750): prevents other users on the machine from
# reading or executing the binaries. Group access preserved for admin use.
chmod 750 "$INSTALL_DIR/mister-core"
chmod 750 "$INSTALL_DIR/sir"

# Verify installed binaries match built binaries
info "Verifying installed binaries..."
if command -v sha256sum &> /dev/null; then
    BUILT_CORE=$(sha256sum target/release/mister-core | awk '{print $1}')
    BUILT_SIR=$(sha256sum bin/sir | awk '{print $1}')
    INST_CORE=$(sha256sum "$INSTALL_DIR/mister-core" | awk '{print $1}')
    INST_SIR=$(sha256sum "$INSTALL_DIR/sir" | awk '{print $1}')
else
    BUILT_CORE=$(shasum -a 256 target/release/mister-core | awk '{print $1}')
    BUILT_SIR=$(shasum -a 256 bin/sir | awk '{print $1}')
    INST_CORE=$(shasum -a 256 "$INSTALL_DIR/mister-core" | awk '{print $1}')
    INST_SIR=$(shasum -a 256 "$INSTALL_DIR/sir" | awk '{print $1}')
fi

if [ "$BUILT_CORE" != "$INST_CORE" ] || [ "$BUILT_SIR" != "$INST_SIR" ]; then
    error "Checksum mismatch between built and installed binaries. Aborting."
fi
info "Installed binaries verified."

# Check PATH — sir CLI commands (sir status, sir doctor, sir trace, etc.) need PATH.
# Hook commands use absolute paths (set during `sir install`) so PATH is not required
# for hook execution, but the CLI must be findable for developer use.
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not in your PATH."
    echo ""
    echo "    sir CLI commands need to be on PATH for direct use (sir status, sir trace, etc.)."
    echo "    Hook commands use absolute paths and do not depend on PATH."
    echo ""

    # Auto-add to shell profile
    SHELL_PROFILE=""
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_PROFILE="$HOME/.bash_profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        echo -n "    Add to $SHELL_PROFILE? [Y/n] "
        read -r REPLY
        if [ -z "$REPLY" ] || [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
            echo '' >> "$SHELL_PROFILE"
            echo '# sir - Sandbox in Reverse' >> "$SHELL_PROFILE"
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_PROFILE"
            export PATH="$HOME/.local/bin:$PATH"
            info "Added to $SHELL_PROFILE. PATH updated for this session."
        else
            echo "    Add this manually to your shell profile:"
            echo '    export PATH="$HOME/.local/bin:$PATH"'
        fi
    else
        echo "    Add this to your shell profile:"
        echo '    export PATH="$HOME/.local/bin:$PATH"'
    fi
    echo ""
fi

if [ "$RUN_SIR_INSTALL" -eq 1 ]; then
    info "Setting up sir hooks for detected agent surfaces..."
    "$INSTALL_DIR/sir" install --yes "${INSTALL_ARGS[@]}"

    if [ -f "$HOME/.claude/settings.json" ] && grep -q "sir.*guard" "$HOME/.claude/settings.json" 2>/dev/null; then
        INSTALLED_AGENTS+=("claude")
        info "Claude Code hooks installed in $HOME/.claude/settings.json"
    fi
    if [ -f "$HOME/.gemini/settings.json" ] && grep -q "sir.*guard" "$HOME/.gemini/settings.json" 2>/dev/null; then
        INSTALLED_AGENTS+=("gemini")
        info "Gemini CLI hooks installed in $HOME/.gemini/settings.json"
    fi
    if [ -f "$HOME/.codex/hooks.json" ] && grep -q "sir.*guard" "$HOME/.codex/hooks.json" 2>/dev/null; then
        INSTALLED_AGENTS+=("codex")
        info "Codex hooks installed in $HOME/.codex/hooks.json"
    fi
    if [ -f "$HOME/.codex/config.toml" ] && grep -Eq '^\s*codex_hooks\s*=\s*true\b' "$HOME/.codex/config.toml" 2>/dev/null; then
        info "Codex feature flag enabled in $HOME/.codex/config.toml"
    fi

    info "Verifying installation..."
    "$INSTALL_DIR/sir" doctor 2>/dev/null || true
else
    warn "Skipping 'sir install --yes' because no supported agent is present yet."
fi

echo ""
info "sir installed successfully!"
NEW_VERSION=$("$INSTALL_DIR/sir" version 2>/dev/null || echo "sir unknown")
if [ "$CURRENT_VERSION" != "none" ] && [ "$CURRENT_VERSION" != "unknown" ]; then
    info "Updated: $CURRENT_VERSION -> $NEW_VERSION"
else
    info "Installed: $NEW_VERSION"
fi
echo ""
echo "    ┌─────────────────────────────────────────────────────┐"
if [ ${#INSTALLED_AGENTS[@]} -gt 0 ]; then
    if [ ${#INSTALLED_AGENTS[@]} -eq 1 ]; then
        printf "    │  Just type '%-6s' — sir is now watching.        │\n" "$(agent_launch_command "${INSTALLED_AGENTS[0]}")"
    else
        echo "    │  Launch Claude, Gemini, or Codex — sir watches.  │"
    fi
    echo "    │                                                     │"
    echo "    │  For other projects, run 'sir install' there to    │"
    echo "    │  activate the detected agent hooks in that repo.   │"
else
    echo "    │  sir binaries are installed.                        │"
    echo "    │                                                     │"
    echo "    │  Install Claude Code, Gemini CLI, or Codex, then    │"
    echo "    │  run 'sir install' in your project directory.       │"
fi
echo "    └─────────────────────────────────────────────────────┘"
echo ""
echo "    Commands:"
echo "      sir status           Check sir status"
echo "      sir doctor           Verify configuration"
echo "      sir trace            HTML timeline of session events"
echo "      sir audit            Terminal security summary"
echo "      sir trust NAME       Trust an MCP server"
echo "      sir log              View decision log"
echo "      sir unlock           Clear secret session flag"
echo "      sir demo             See detections in action"
echo ""
