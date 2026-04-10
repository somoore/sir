#!/usr/bin/env bash
# Generate SHA-256 and SHA-512 checksums for sir release artifacts.
# Usage: ./scripts/checksum.sh [directory]
#   directory: path containing binaries to checksum (default: ./bin/)
set -euo pipefail

ARTIFACT_DIR="${1:-./bin}"

if [ ! -d "$ARTIFACT_DIR" ]; then
    echo "Error: artifact directory '$ARTIFACT_DIR' does not exist." >&2
    exit 1
fi

# Collect all files (non-directories) in the artifact directory
FILES=()
while IFS= read -r -d '' file; do
    FILES+=("$file")
done < <(find "$ARTIFACT_DIR" -maxdepth 1 -type f -print0 | sort -z)

if [ ${#FILES[@]} -eq 0 ]; then
    echo "Error: no files found in '$ARTIFACT_DIR'." >&2
    exit 1
fi

# Generate SHA-256
SHA256_FILE="CHECKSUMS.sha256"
echo "Generating $SHA256_FILE..."
> "$SHA256_FILE"
for file in "${FILES[@]}"; do
    basename=$(basename "$file")
    if command -v sha256sum &> /dev/null; then
        hash=$(sha256sum "$file" | awk '{print $1}')
    else
        hash=$(shasum -a 256 "$file" | awk '{print $1}')
    fi
    echo "$hash  $basename" >> "$SHA256_FILE"
done
echo "  Written: $SHA256_FILE"

# Generate SHA-512
SHA512_FILE="CHECKSUMS.sha512"
echo "Generating $SHA512_FILE..."
> "$SHA512_FILE"
for file in "${FILES[@]}"; do
    basename=$(basename "$file")
    if command -v sha512sum &> /dev/null; then
        hash=$(sha512sum "$file" | awk '{print $1}')
    else
        hash=$(shasum -a 512 "$file" | awk '{print $1}')
    fi
    echo "$hash  $basename" >> "$SHA512_FILE"
done
echo "  Written: $SHA512_FILE"

echo ""
echo "=== SHA-256 ==="
cat "$SHA256_FILE"
echo ""
echo "=== SHA-512 ==="
cat "$SHA512_FILE"
