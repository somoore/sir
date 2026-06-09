#!/usr/bin/env bash
# Reject commit messages that mark a commit as AI-assisted or co-authored.
#
# Shared logic for three enforcement layers:
#   - local commit-msg hook (.githooks/commit-msg)        — fast feedback, bypassable
#   - CI status check (.github/workflows/no-assisted-commits.yml) — PR gate
#   - GitHub ruleset commit_message_pattern               — non-bypassable push gate
#
# The ruleset regex is kept in lockstep with $PATTERN below; if you change one,
# change both and re-run scripts/apply-commit-policy-ruleset.sh.
#
# Usage:
#   check-no-assisted-commits.sh <file-with-message>   # check a single message (hook)
#   check-no-assisted-commits.sh --range <base>..<head> # check a commit range (CI)
set -euo pipefail

# Case-insensitive markers, anchored to the start of a line so that prose that
# merely *mentions* a trailer (e.g. this policy's own commit message) does not
# trip the check — only real trailers/footers do. Leading whitespace tolerated.
# Keep aligned with the ruleset pattern in apply-commit-policy-ruleset.sh.
PATTERN='^[[:space:]]*(co-authored-by:|assisted-by:|🤖[[:space:]]*generated with|generated with \[?(claude|codex))'

fail() {
	echo "✖ Rejected: commit message marks this commit as AI-assisted or co-authored." >&2
	echo "  Offending commit: ${1:-<staged message>}" >&2
	echo "  Matched marker(s):" >&2
	echo "$2" | sed 's/^/    /' >&2
	echo >&2
	echo "  This repository does not accept Co-authored-by:, Assisted-by:, or AI-tool" >&2
	echo "  generation footers. Remove the trailer/footer and recommit." >&2
	exit 1
}

check_message() {
	# $1 = label, $2 = message text
	local label="$1" msg="$2" hits
	hits="$(printf '%s\n' "$msg" | grep -iE "$PATTERN" || true)"
	if [ -n "$hits" ]; then
		fail "$label" "$hits"
	fi
}

if [ "${1:-}" = "--range" ]; then
	range="${2:?usage: --range <base>..<head>}"
	rc=0
	while IFS= read -r sha; do
		[ -z "$sha" ] && continue
		msg="$(git log -1 --format='%B' "$sha")"
		hits="$(printf '%s\n' "$msg" | grep -iE "$PATTERN" || true)"
		if [ -n "$hits" ]; then
			echo "✖ ${sha:0:9} $(git log -1 --format='%s' "$sha")" >&2
			printf '%s\n' "$hits" | sed 's/^/    /' >&2
			rc=1
		fi
	done < <(git rev-list "$range")
	if [ "$rc" -ne 0 ]; then
		echo >&2
		echo "One or more commits are marked AI-assisted/co-authored. See above." >&2
		exit 1
	fi
	echo "✔ No assisted/co-authored commit messages in $range"
	exit 0
fi

# Single-message mode (commit-msg hook): $1 is the path to the message file.
msgfile="${1:?usage: check-no-assisted-commits.sh <message-file> | --range <base>..<head>}"
check_message "<staged message>" "$(cat "$msgfile")"
exit 0
