#!/usr/bin/env bash
set -euo pipefail

echo "sir -- Uninstall"
echo "================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

echo "This will remove ALL sir components from your system:"
echo ""
echo "  Binaries:"
echo "    ~/.local/bin/sir"
echo "    ~/.local/bin/mister-core"
echo ""
echo "  Global hooks:"
echo "    ~/.claude/settings.json  (sir hook entries will be removed)"
echo ""
echo "  State data:"
echo "    ~/.sir/  (all project state, ledgers, leases, session data)"
echo ""

echo -e "${RED}This action is irreversible. All sir log history will be lost.${NC}"
echo ""
echo -n "Type 'delete' to confirm removal of ALL sir data: "
read -r CONFIRM

if [ "$CONFIRM" != "delete" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""

# Remove binaries
if [ -f "$HOME/.local/bin/sir" ]; then
    rm "$HOME/.local/bin/sir"
    info "Removed ~/.local/bin/sir"
else
    warn "~/.local/bin/sir not found (already removed?)"
fi

if [ -f "$HOME/.local/bin/mister-core" ]; then
    rm "$HOME/.local/bin/mister-core"
    info "Removed ~/.local/bin/mister-core"
else
    warn "~/.local/bin/mister-core not found (already removed?)"
fi

# Remove sir hooks from global settings.json (preserve other settings)
GLOBAL_SETTINGS="$HOME/.claude/settings.json"
if [ -f "$GLOBAL_SETTINGS" ]; then
    if grep -q "sir guard" "$GLOBAL_SETTINGS" 2>/dev/null; then
        # Use python3 to remove just the hooks key, preserving other settings
        if command -v python3 &> /dev/null; then
            python3 - "$GLOBAL_SETTINGS" <<'PYEOF' 2>/dev/null
import sys, json
path = sys.argv[1]
with open(path) as f:
    settings = json.load(f)
if 'hooks' in settings:
    del settings['hooks']
with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
PYEOF
            info "Removed sir hooks from $GLOBAL_SETTINGS (other settings preserved)"
        else
            warn "python3 not found — manually remove the 'hooks' key from $GLOBAL_SETTINGS"
        fi
    else
        warn "$GLOBAL_SETTINGS does not contain sir hooks (left untouched)"
    fi
else
    warn "$GLOBAL_SETTINGS not found"
fi

# Also clean up old-style hooks.json if it exists
OLD_HOOKS="$HOME/.claude/hooks/hooks.json"
if [ -f "$OLD_HOOKS" ] && grep -q "sir guard" "$OLD_HOOKS" 2>/dev/null; then
    rm "$OLD_HOOKS"
    info "Removed legacy hooks file $OLD_HOOKS"
fi

# Remove all sir state
if [ -d "$HOME/.sir" ]; then
    # Count projects for user awareness
    PROJECT_COUNT=$(find "$HOME/.sir/projects" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    rm -rf "$HOME/.sir"
    info "Removed ~/.sir/ ($PROJECT_COUNT project(s) of state data)"
else
    warn "~/.sir/ not found (already removed?)"
fi

# Remove per-project .claude/.sir/ directories in current directory if present
if [ -d ".claude/.sir" ]; then
    rm -rf ".claude/.sir"
    info "Removed .claude/.sir/ in current directory"
fi

# Check for PATH entry in shell profiles and notify
for PROFILE in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if [ -f "$PROFILE" ] && grep -q "# sir - Sandbox in Reverse" "$PROFILE" 2>/dev/null; then
        warn "PATH entry for sir found in $PROFILE"
        echo "    You may want to remove these lines:"
        echo "      # sir - Sandbox in Reverse"
        echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
    fi
done

echo ""
info "sir has been completely uninstalled."
echo ""
echo "    To reinstall: sh install.sh"
echo ""
