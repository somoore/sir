#!/usr/bin/env bash
# Verify sir binaries against published checksums.
# Usage: ./scripts/verify-checksums.sh [checksum-file] [directory]
#   checksum-file: path to CHECKSUMS.sha256 (default: ./CHECKSUMS.sha256)
#   directory:     path containing binaries to verify (default: ./bin/)
set -euo pipefail

CHECKSUM_FILE="${1:-./CHECKSUMS.sha256}"
ARTIFACT_DIR="${2:-./bin}"

if [ ! -f "$CHECKSUM_FILE" ]; then
    echo "Error: checksum file '$CHECKSUM_FILE' not found." >&2
    echo "" >&2
    echo "To download from a release:" >&2
    echo "  curl -fsSL https://github.com/somoore/sir/releases/download/vX.Y.Z/CHECKSUMS.sha256 -o CHECKSUMS.sha256" >&2
    exit 1
fi

if [ ! -d "$ARTIFACT_DIR" ]; then
    echo "Error: artifact directory '$ARTIFACT_DIR' does not exist." >&2
    exit 1
fi

FAILURES=0
VERIFIED=0

echo "Verifying checksums from $CHECKSUM_FILE against $ARTIFACT_DIR..."
echo ""

while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    expected_hash=$(echo "$line" | awk '{print $1}')
    filename=$(echo "$line" | awk '{print $2}')
    filepath="$ARTIFACT_DIR/$filename"

    if [ ! -f "$filepath" ]; then
        echo "MISSING: $filename"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    if command -v sha256sum &> /dev/null; then
        actual_hash=$(sha256sum "$filepath" | awk '{print $1}')
    else
        actual_hash=$(shasum -a 256 "$filepath" | awk '{print $1}')
    fi

    if [ "$expected_hash" = "$actual_hash" ]; then
        echo "OK:      $filename"
        VERIFIED=$((VERIFIED + 1))
    else
        echo "FAILED:  $filename"
        echo "  Expected: $expected_hash"
        echo "  Actual:   $actual_hash"
        FAILURES=$((FAILURES + 1))
    fi
done < "$CHECKSUM_FILE"

echo ""
echo "Verified: $VERIFIED  Failed: $FAILURES"

if [ "$FAILURES" -gt 0 ]; then
    echo "" >&2
    echo "CHECKSUM VERIFICATION FAILED — do not use these binaries." >&2
    exit 1
fi

echo "All checksums verified."
