#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-}"
DEST_DIR="${2:-./verify-release}"
REPO="${SIR_RELEASE_REPO:-somoore/sir}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

usage() {
  cat <<'EOF'
Usage: ./scripts/verify-release.sh <tag> [download-dir]

Downloads a published sir release and verifies:
  1. cosign signatures on every archive
  2. the signed checksums manifest
  3. the signed AIBOM
  4. SLSA provenance for every archive
  5. checksums.txt against the downloaded archives
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    exit 1
  fi
}

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check checksums.txt
  else
    shasum -a 256 --check checksums.txt
  fi
}

require_checksum_targets() {
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    target="${line#* }"
    target="${target# }"
    if [[ -z "${target}" || "${target}" == "${line}" ]]; then
      echo "Malformed checksums.txt entry: ${line}" >&2
      exit 1
    fi
    if [[ ! -f "${target}" ]]; then
      echo "checksums.txt references missing file: ${target}" >&2
      exit 1
    fi
  done < checksums.txt
}

if [[ -z "${TAG}" ]]; then
  usage >&2
  exit 1
fi

need_cmd gh
need_cmd cosign
need_cmd python3
# slsa-verifier is optional — used only when sir.intoto.jsonl is present
if [[ -z "$(command -v slsa-verifier 2>/dev/null)" ]]; then
  echo "Note: slsa-verifier not found. SLSA provenance check will be skipped if present."
fi

mkdir -p "${DEST_DIR}"
gh release download "${TAG}" --repo "${REPO}" --dir "${DEST_DIR}"

shopt -s nullglob
archives=("${DEST_DIR}"/sir_*.tar.gz)
shopt -u nullglob
if [[ ${#archives[@]} -eq 0 ]]; then
  echo "No sir release archives found in ${DEST_DIR}" >&2
  exit 1
fi

for required in checksums.txt checksums.txt.sig checksums.txt.pem aibom.json aibom.json.sig aibom.json.pem; do
  if [[ ! -f "${DEST_DIR}/${required}" ]]; then
    echo "Missing required release artifact: ${DEST_DIR}/${required}" >&2
    exit 1
  fi
done

CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
SOURCE_URI="github.com/${REPO}"

echo "==> Verifying archive signatures"
for archive in "${archives[@]}"; do
  cosign verify-blob \
    --certificate "${archive}.pem" \
    --signature "${archive}.sig" \
    --certificate-identity "${CERT_IDENTITY}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    "${archive}"
done

echo "==> Verifying signed checksums manifest"
cosign verify-blob \
  --certificate "${DEST_DIR}/checksums.txt.pem" \
  --signature "${DEST_DIR}/checksums.txt.sig" \
  --certificate-identity "${CERT_IDENTITY}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${DEST_DIR}/checksums.txt"

echo "==> Verifying signed AIBOM"
cosign verify-blob \
  --certificate "${DEST_DIR}/aibom.json.pem" \
  --signature "${DEST_DIR}/aibom.json.sig" \
  --certificate-identity "${CERT_IDENTITY}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${DEST_DIR}/aibom.json"

if [[ -f "${DEST_DIR}/sir.intoto.jsonl" ]]; then
  echo "==> Verifying SLSA provenance"
  for archive in "${archives[@]}"; do
    slsa-verifier verify-artifact "${archive}" \
      --provenance-path "${DEST_DIR}/sir.intoto.jsonl" \
      --source-uri "${SOURCE_URI}" \
      --source-tag "${TAG}"
  done
else
  echo "==> SLSA provenance (sir.intoto.jsonl) not present — skipping."
  echo "    This is expected while slsa-github-generator v2.1.0 exit-27 bug is unresolved."
fi

echo "==> Verifying checksums manifest against downloaded archives"
(
  cd "${DEST_DIR}"
  require_checksum_targets
  sha256_check
)

echo "==> Verifying AIBOM zero-ML declaration"
python3 - "${DEST_DIR}/aibom.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)

for field in ("ml_components", "model_weights", "training_data", "prompts", "embeddings", "fine_tuning"):
    value = doc.get(field, [])
    if not isinstance(value, list):
        raise SystemExit(f"{path}: expected {field} to be a list, found {type(value).__name__}")
    if value:
        raise SystemExit(f"{path}: expected empty {field}, found {value!r}")

deps = doc.get("model_dependencies", {})
if not isinstance(deps, dict):
    raise SystemExit(f"{path}: expected model_dependencies to be an object, found {type(deps).__name__}")
for field in ("build_time", "runtime", "optional"):
    value = deps.get(field, [])
    if not isinstance(value, list):
        raise SystemExit(
            f"{path}: expected model_dependencies.{field} to be a list, found {type(value).__name__}"
        )
    if value:
        raise SystemExit(f"{path}: expected empty model_dependencies.{field}, found {value!r}")

print(f"{path}: zero-ML declaration verified")
PY

echo
echo "Release ${TAG} verified successfully."
