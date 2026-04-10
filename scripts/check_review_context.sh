#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z "${repo_root}" ]]; then
  echo "FAIL: not inside a git repository"
  exit 1
fi

cd "${repo_root}"

default_ref=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null || true)
default_ref=${default_ref#refs/remotes/}
if [[ -z "${default_ref}" ]]; then
  default_ref="origin/main"
fi

branch=$(git rev-parse --abbrev-ref HEAD)
dirty=$(git status --porcelain)

echo "repo:    ${repo_root}"
echo "branch:  ${branch}"
echo "default: ${default_ref}"

if [[ -n "${dirty}" ]]; then
  echo
  echo "FAIL: working tree is dirty. Review and branch hygiene checks only make sense from a clean worktree."
  git status --short
  exit 1
fi

if [[ "${branch}" == "HEAD" ]]; then
  echo
  echo "FAIL: detached HEAD. Start work from a named topic branch based on current main."
  exit 1
fi

if [[ "${branch}" == "${default_ref#origin/}" ]]; then
  echo
  echo "FAIL: you are on the default branch. Start from a fresh topic branch before editing security-sensitive code."
  exit 1
fi

if git rev-parse --verify "${default_ref}" >/dev/null 2>&1; then
  ahead=$(git rev-list --count "${default_ref}..HEAD")
  behind=$(git rev-list --count "HEAD..${default_ref}")
  merge_base=$(git merge-base HEAD "${default_ref}")
  default_sha=$(git rev-parse "${default_ref}")
  echo "ahead:   ${ahead}"
  echo "behind:  ${behind}"
  if [[ "${merge_base}" != "${default_sha}" || "${behind}" != "0" ]]; then
    echo
    echo "FAIL: branch is not based on current ${default_ref}. Rebase or create a new branch from the current default branch before proceeding."
    exit 1
  fi
else
  echo
  echo "WARN: ${default_ref} is not available locally. Run 'git fetch origin' before using this check for review readiness."
fi

echo
echo "OK: clean worktree, named topic branch, and branch base matches ${default_ref}."
