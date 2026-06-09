#!/usr/bin/env bash
# Create/update the GitHub ruleset that rejects AI-assisted / co-authored commits
# on ALL branches at push time. This is the non-bypassable enforcement layer.
#
# The regex here MUST stay aligned with $PATTERN in check-no-assisted-commits.sh.
# Requires: gh CLI authenticated with admin on the repo, and python3.
set -euo pipefail

REPO="${1:-somoore/sir}"
RULESET_NAME="Block assisted/co-authored commits"

# GitHub ruleset regex (RE2). Case-insensitivity via inline (?i); (?m) so ^
# anchors per line. Mirrors the line-anchored matcher in
# check-no-assisted-commits.sh: only real trailers/footers match, not prose.
PATTERN='(?im)^[[:space:]]*(co-authored-by:|assisted-by:|🤖[[:space:]]*generated with|generated with \[?(claude|codex))'

# Build the JSON payload with python3 so the regex backslashes and the emoji are
# encoded safely (shell heredocs mangle both).
payload="$(RULESET_NAME="$RULESET_NAME" PATTERN="$PATTERN" python3 - <<'PY'
import json, os
print(json.dumps({
    "name": os.environ["RULESET_NAME"],
    "target": "branch",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
    "rules": [{
        "type": "commit_message_pattern",
        "parameters": {
            "name": "No assisted or co-authored commits",
            "negate": True,
            "operator": "regex",
            "pattern": os.environ["PATTERN"],
        },
    }],
}))
PY
)"

existing_id="$(gh api "repos/${REPO}/rulesets" --jq ".[] | select(.name==\"${RULESET_NAME}\") | .id" 2>/dev/null || true)"

if [ -n "$existing_id" ]; then
	echo "Updating existing ruleset id=${existing_id}"
	printf '%s' "$payload" | gh api -X PUT "repos/${REPO}/rulesets/${existing_id}" --input - \
		--jq '{id, name, enforcement, scope: .conditions.ref_name.include}'
else
	echo "Creating new ruleset"
	printf '%s' "$payload" | gh api -X POST "repos/${REPO}/rulesets" --input - \
		--jq '{id, name, enforcement, scope: .conditions.ref_name.include}'
fi
