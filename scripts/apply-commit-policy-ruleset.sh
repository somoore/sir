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
#
# co-authored-by handling mirrors check-no-assisted-commits.sh, which exempts
# a trailer whose name contains a COMPLETE `[bot]` immediately before the
# email. RE2 has no lookahead, so the exemption is a tempered loop that can
# consume anything except a `[bot]` - including `[bot` followed by something
# other than `]`, which is what keeps `Alice [bot reviewer <a@b>` blocked
# (only a closing `]` grants the exemption). A trailing incomplete bracket
# prefix is absorbed before the end anchor so `... [`, `[b`, `[bo`, `[bot` and
# `[bot]` with no email still match (are rejected).
#
# Loop alternatives, in order:
#     [^<bracket><newline>            any char but an opening bracket
#     <bracket>[^b<newline>           an opening bracket not starting the marker
#     <bracket>b[^o<newline>          `[b` not starting the marker
#     <bracket>bo[^t<newline>         `[bo` not starting the marker
#     <bracket>bot[^close<newline>    `[bot` not closing the marker
# Final group: absorb a trailing incomplete prefix before the end anchor.
#
# The hook reaches the same verdicts with a simpler two-step grep (base
# pattern plus a `[bot] <` exemption filter); see check-no-assisted-commits.sh.
PATTERN='(?im)^[[:space:]]*(assisted-by:|🤖[[:space:]]*generated with|generated with \[?(claude|codex)|co-authored-by:(?:[^\[\n]|\[[^b\n]|\[b[^o\n]|\[bo[^t\n]|\[bot[^\]\n])*(?:\[(?:b(?:o(?:t)?)?)?\]?)?$)'

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

# GitHub rejects commit_message_pattern on repositories where the rule type is
# not available, with a bare "Invalid rule" 422. Say so instead of leaving a
# confusing API error: enforcement still happens in the commit-msg hook and in
# the no-assisted-commits CI check.
if ! gh api "repos/${REPO}/rulesets" >/dev/null 2>&1; then
	echo "gh cannot list rulesets for ${REPO}; check auth and admin rights." >&2
	exit 1
fi

apply() {
	# $1 = method, $2 = path
	printf '%s' "$payload" | gh api -X "$1" "$2" --input - \
		--jq '{id, name, enforcement, scope: .conditions.ref_name.include}'
}

if [ -n "$existing_id" ]; then
	echo "Updating existing ruleset id=${existing_id}"
	if ! output="$(apply PUT "repos/${REPO}/rulesets/${existing_id}")"; then
		echo "The ruleset could not be updated; GitHub rejected commit_message_pattern." >&2
		echo "This repository or plan does not support that rule type, so the" >&2
		echo "non-bypassable push layer cannot exist here. Enforcement remains with" >&2
		echo "the commit-msg hook and the no-assisted-commits CI check." >&2
		exit 1
	fi
	echo "$output"
else
	echo "Creating new ruleset"
	if ! output="$(apply POST "repos/${REPO}/rulesets")"; then
		echo "The ruleset could not be created; GitHub rejected commit_message_pattern." >&2
		echo "This repository or plan does not support that rule type, so the" >&2
		echo "non-bypassable push layer cannot exist here. Enforcement remains with" >&2
		echo "the commit-msg hook and the no-assisted-commits CI check." >&2
		exit 1
	fi
	echo "$output"
fi
