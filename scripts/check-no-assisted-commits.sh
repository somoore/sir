#!/usr/bin/env bash
# Reject commit messages that mark a commit as AI-assisted or co-authored.
#
# Shared logic for three enforcement layers:
#   - local commit-msg hook (.githooks/commit-msg)        — fast feedback, bypassable
#   - CI status check (.github/workflows/no-assisted-commits.yml) — PR gate
#   - GitHub ruleset commit_message_pattern               — AI-marker push gate
#
# The server-side ruleset rejects the AI-specific subset of $PATTERN. GitHub's
# RE2 ruleset syntax cannot express the exact Dependabot exception below, so
# co-author policy is enforced by this script in the hook and required CI check.
#
# Usage:
#   check-no-assisted-commits.sh <file-with-message>   # check a single message (hook)
#   check-no-assisted-commits.sh --range <base>..<head> # check a commit range (CI)
set -euo pipefail

# Case-insensitive markers, anchored to the start of a line so that prose that
# merely *mentions* a trailer (e.g. this policy's own commit message) does not
# trip the check — only real trailers/footers do. Leading whitespace tolerated.
PATTERN='^[[:space:]]*(co-authored-by:|assisted-by:|🤖[[:space:]]*generated with|generated with \[?(claude|codex))'
TRUSTED_DEPENDABOT_TRAILER='^[[:space:]]*co-authored-by:[[:space:]]*dependabot\[bot\][[:space:]]*<49699333\+dependabot\[bot\]@users\.noreply\.github\.com>[[:space:]]*$'

find_hits() {
	grep -iE "$PATTERN" || true
}

is_verified_dependabot_commit() {
	local sha="$1" metadata response

	# Text attribution is forgeable. Require both the immutable git identities
	# and GitHub's valid-signature record for the Dependabot-authored commit.
	metadata="$(git show -s --format='%an|%ae|%cn|%ce' "$sha")"
	[ "$metadata" = 'dependabot[bot]|49699333+dependabot[bot]@users.noreply.github.com|GitHub|noreply@github.com' ] || return 1
	[ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_TOKEN:-}" ] || return 1

	response="$(
		curl --fail --silent --show-error --retry 2 \
			-H "Authorization: Bearer $GITHUB_TOKEN" \
			-H 'Accept: application/vnd.github+json' \
			-H 'X-GitHub-Api-Version: 2022-11-28' \
			"https://api.github.com/repos/${GITHUB_REPOSITORY}/commits/${sha}"
	)"
	printf '%s' "$response" | python3 -c '
import json, sys
c = json.load(sys.stdin)
ok = (
    c.get("author", {}).get("login") == "dependabot[bot]"
    and c.get("committer", {}).get("login") == "web-flow"
    and c.get("commit", {}).get("verification", {}).get("verified") is True
    and c.get("commit", {}).get("verification", {}).get("reason") == "valid"
)
raise SystemExit(0 if ok else 1)
'
}

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
	hits="$(printf '%s\n' "$msg" | find_hits)"
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
		hits="$(printf '%s\n' "$msg" | find_hits)"
		if [ -n "$hits" ]; then
			non_dependabot_hits="$(printf '%s\n' "$hits" | grep -ivE "$TRUSTED_DEPENDABOT_TRAILER" || true)"
			if [ -z "$non_dependabot_hits" ] && is_verified_dependabot_commit "$sha"; then
				echo "✔ ${sha:0:9} verified Dependabot merge trailer"
				continue
			fi
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
