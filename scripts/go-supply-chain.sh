#!/usr/bin/env bash
# Verify Go module integrity for sir.
# Checks that go.sum exists (if deps exist), modules are tidy,
# and no unexpected changes have been introduced.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FAILURES=0

echo "sir Go Supply Chain Verification"
echo "================================="
echo ""

# 1. Check Go version is pinned in go.mod
GO_VERSION=$(grep '^go ' go.mod | awk '{print $2}')
if [ -z "$GO_VERSION" ]; then
    fail "No Go version specified in go.mod"
    FAILURES=$((FAILURES + 1))
else
    ok "Go version pinned in go.mod: $GO_VERSION"
fi

# 2. Check go.mod is tidy
# Note: go mod tidy -diff requires Go 1.23+; use git status instead.
go mod tidy 2>/dev/null
TIDY_DIRTY=$(git status --porcelain go.mod go.sum 2>/dev/null || true)
if [ -n "$TIDY_DIRTY" ]; then
    fail "go.mod is not tidy. Run 'go mod tidy' and commit changes."
    echo "$TIDY_DIRTY"
    FAILURES=$((FAILURES + 1))
else
    ok "go.mod is tidy"
fi

# 3. Check for go.sum if there are dependencies
DEP_COUNT=$(grep -c '^require' go.mod 2>/dev/null) || DEP_COUNT=0
if [ "$DEP_COUNT" -gt 0 ]; then
    if [ ! -f go.sum ]; then
        fail "go.sum missing but go.mod has dependencies"
        FAILURES=$((FAILURES + 1))
    else
        ok "go.sum exists"
        # Verify go.sum integrity
        if go mod verify 2>&1 | grep -q "all modules verified"; then
            ok "All module checksums verified (go mod verify)"
        else
            VERIFY_OUT=$(go mod verify 2>&1)
            if echo "$VERIFY_OUT" | grep -qi "error\|SECURITY"; then
                fail "Module verification failed:"
                echo "$VERIFY_OUT"
                FAILURES=$((FAILURES + 1))
            else
                ok "Module integrity check passed"
            fi
        fi
    fi
else
    ok "No external dependencies (go.sum not required)"
fi

# 4. Check for version ranges or 'latest' in go.mod
if grep -qE '(latest|v0\.0\.0-|>=|<=|~|\\^)' go.mod 2>/dev/null; then
    fail "go.mod contains unpinned or floating dependency versions"
    FAILURES=$((FAILURES + 1))
else
    ok "All dependency versions are pinned"
fi

# 5. Check for replace directives (supply chain risk)
if grep -q '^replace' go.mod 2>/dev/null; then
    warn "go.mod contains 'replace' directives — review for supply chain risk"
else
    ok "No 'replace' directives in go.mod"
fi

# 6. Run govulncheck if available
if command -v govulncheck &> /dev/null; then
    echo ""
    echo "Running govulncheck..."
    if govulncheck ./... 2>&1; then
        ok "govulncheck: no known vulnerabilities"
    else
        fail "govulncheck found vulnerabilities"
        FAILURES=$((FAILURES + 1))
    fi
else
    warn "govulncheck not installed (install: go install golang.org/x/vuln/cmd/govulncheck@v1.1.4)"
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
    echo -e "${RED}Supply chain verification FAILED ($FAILURES issues)${NC}"
    exit 1
fi

echo -e "${GREEN}Supply chain verification PASSED${NC}"
