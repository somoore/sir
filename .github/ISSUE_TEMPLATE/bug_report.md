---
name: Bug Report
about: Report a bug in sir
title: "[bug] "
labels: bug
assignees: ''
---

## Describe the bug

A clear description of what happened.

## Optional intake context

If you already know any of these, include them. Maintainers can fill the rest during triage.

- **Affected agent (if known):** (Claude / Gemini / Codex / multiple / none)
- **Anything security-sensitive about this report?:** (brief note, optional)

## Steps to reproduce

1. Run `sir install` in a project directory
2. Start the affected agent (`claude`, `gemini`, or `codex`)
3. Ask the agent to do X
4. sir does Y (unexpected)

## Expected behavior

What you expected sir to do.

## Actual behavior

What sir actually did. Include the full terminal output if possible.

## Ledger output

If relevant, include the output of `sir log` (last 10 entries) or `sir explain <verdict-hash>`:

```
(paste sir log output here)
```

## Environment

- **sir version:** (`sir --version`)
- **OS:** (e.g., macOS 15.4, Ubuntu 24.04)
- **Architecture:** (e.g., arm64, x86_64)
- **Go version:** (`go version`)
- **Rust version:** (`rustc --version`)
- **Agent + version:** (Claude Code / Gemini CLI / Codex, if known)

## Doctor output

Output of `sir doctor`:

```
(paste sir doctor output here)
```

## Additional context

Any other context about the problem. If this is a security bypass (sir allowed something it should have blocked), please consider reporting it via the security vulnerability process instead (see SECURITY.md).
