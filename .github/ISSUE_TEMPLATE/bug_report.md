---
name: Bug Report
about: Report a bug in sir
title: "[bug] "
labels: bug
assignees: ''
---

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

> **Note:** sir is experimental. It is a small-team project and triage is best-effort. We read every report, but response time varies and not every issue will get an immediate fix. The best reports include the ledger output and reproduction steps below — those unblock triage fastest.
>
> **Warning:** If this looks like a security bypass (sir allowed something it should have blocked, or a way to disable sir without detection), please use the private security vulnerability process instead. See [SECURITY.md](../../SECURITY.md).

## Describe the bug

A clear description of what happened. If you know which part of sir is involved (hooks, policy oracle, ledger, MCP scanning, install/doctor, runtime containment), say so.

## Optional intake context

If you already know any of these, include them. Maintainers can fill the rest during triage.

- **Affected agent (if known):** Claude, Gemini, Codex, multiple, or none.
- **Anything security-sensitive about this report?:** brief note, optional.

## Steps to reproduce

1. Run `sir install` in a project directory.
2. Start the affected agent (`claude`, `gemini`, or `codex`).
3. Ask the agent to do X.
4. sir does Y (unexpected).

## Expected behavior

What you expected sir to do.

## Actual behavior

What sir actually did. Include the full terminal output if possible.

## Ledger output

If relevant, include the output of `sir log` (last 10 entries) or `sir explain <verdict-hash>`:

```text
(paste sir log output here)
```

## Environment

- **sir version:** `sir --version`
- **OS:** for example, macOS 15.4 or Ubuntu 24.04.
- **Architecture:** for example, `arm64` or `x86_64`.
- **Go version:** `go version`
- **Rust version:** `rustc --version`
- **Agent and version:** Claude Code, Gemini CLI, or Codex, if known.

## Doctor output

Output of `sir doctor`:

```text
(paste sir doctor output here)
```

## Additional context

Any other context about the problem — recent changes to your environment, the specific agent prompt that triggered it, whether this reproduces on a fresh `sir install`, and whether `sir doctor` reports anything unexpected.
