# sir — Sandbox in Reverse

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

> A local, hook-mediated security runtime for AI coding agents. Quiet on normal coding. Loud on dangerous transitions.

<div align="center">

[![Pre-alpha release](https://img.shields.io/github/v/release/somoore/sir?include_prereleases&label=pre-alpha&color=orange)](https://github.com/somoore/sir/releases/latest) [![Supports](https://img.shields.io/badge/supports-Claude_%7C_Gemini_%7C_Codex-blueviolet)](#supported-agents) [![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](#hard-limits)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/somoore/sir/badge)](https://securityscorecards.dev/viewer/?uri=github.com/somoore/sir) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12462/badge)](https://www.bestpractices.dev/projects/12462) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

</div>

Traditional sandboxes constrain a process from below — syscall filters, filesystem jails, namespaces. **We built sir to constrain the agent from above.** sir intercepts tool calls at the hook layer, decides allow / ask / deny against a local policy oracle, and writes every verdict to an immutable hash-chained ledger. The agent never knows it's being watched until it tries something dangerous.

We don't think sandboxes are *wrong* — we think they're incomplete for AI coding agents, because:

- Agents don't run as a single process you can sandbox. They orchestrate tools, spawn subprocesses, and call MCP servers.
- The dangerous surface isn't syscalls — it's *intents*: "read `.env`, then `curl` an external host." No syscall filter sees that as one risky operation.
- A traditional sandbox can't express "allow this network call *unless* the agent just read a secret file."

sir is defense in depth for the layer where AI coding agents actually operate. The information flow control lattice in [`mister-core/src/ifc.rs`](mister-core/src/ifc.rs) is the load-bearing piece: read `.env`, and that taint propagates to any file the agent writes, any commit it makes, any push it attempts. That's real IFC, not a blocklist.

## What it is

- **Go CLI (`sir`)** — collects facts on every tool call, manages session state, writes the ledger.
- **Rust policy oracle (`mister-core`)** — zero-dependency, zero-unsafe. Decides allow / ask / deny.
- **Hash-chained ledger** — append-only, verifiable with `sir log verify`. No daemon, no phone-home, no external dependency on the normal path.

```mermaid
flowchart LR
    A[AI Coding Agent] -->|tool call| H[sir hook handler<br/>Go]
    H -->|facts + session state| R[mister-core<br/>Rust policy oracle]
    R -->|allow / ask / deny| H
    H -->|decision + evidence| L[(hash-chained<br/>ledger)]
    H -->|verdict| A
```

<!-- BEGIN GENERATED SUPPORT SUMMARY -->
- **Claude Code** — **Reference support.** Full 10-hook lifecycle with native interactive approval and complete tool-path coverage.
- **Gemini CLI** — **Near-parity support.** 6 hook events fire on Gemini CLI 0.36.0+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [gemini-support.md](docs/user/gemini-support.md).
- **Codex** — **Limited support.** 5 hook events fire on `codex-cli` 0.118.0+ after enabling the `codex_hooks` feature flag (`codex features enable codex_hooks`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See [codex-support.md](docs/user/codex-support.md).
<!-- END GENERATED SUPPORT SUMMARY -->

## Why use sir

- **Secrets and taint propagation.** Agents touch `.env`, cloud credentials, and SSH keys in the same session where they run shell and push code. Information flow control (IFC) tracks the taint: a secret read contaminates every downstream write, commit, or push attempt.
- **MCP prompt injection.** MCP servers are an injection surface. sir scans MCP arguments for credentials and MCP responses for known injection patterns, taints untrusted servers, and forces re-approval after a hit.
- **A local audit trail.** Provider logs stop at the governance layer. sir writes a tamper-evident record of what the agent actually did on your machine — the same chain a forensic review would trust.
- **Quiet on normal coding, loud on dangerous transitions.** Reads, edits, tests, commits, and loopback traffic stay silent. Only external network, secret egress, posture tampering, and MCP injection trigger prompts or denials.

## Install in 3 minutes

Fastest path — `install.sh` drops `sir` into `~/.local/bin`, preserves any existing `~/.sir/` state, and is the only supported update path. There is no self-updater.

```bash
curl -sSL https://raw.githubusercontent.com/somoore/sir/main/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent codex
```

Build from source if you prefer:

```bash
# Requires [Rust 1.94.0+](https://rustup.rs/)
# Requires [Go 1.22+](https://go.dev/dl/) with toolchain auto-fetch to go1.25.9
make build
make install
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent gemini
```

Managed rollout:

```bash
export SIR_MANAGED_POLICY_PATH=/etc/sir/managed-policy.json
sir install --agent claude
```

## Prove it works

Run the baseline checks — hooks installed, posture intact, ledger chain verifies:

```bash
sir status       # hooks installed, session posture, last contained-run info
sir doctor       # hook subtree intact, ledger chain verifies, sentinels unchanged
sir log verify   # walk the hash chain and report first corruption, if any
```

Then trigger one real protection path in your agent:

1. Ask the agent to read `.env`.
2. Approve the prompt. sir labels the read as secret and marks the session tainted. You'll see the following in the agent's terminal:

   ```text
   sir: credentials file read (.env). External network requests are now restricted.
   sir: this is turn-scoped — clears when the agent finishes responding.
   sir: to clear now: sir unlock
   ```

3. In the same turn, ask it to `curl https://httpbin.org/get`. sir denies the tool call before it runs.
4. Run `sir explain --last` to see the full causal chain: which sensitive read tainted the session, which verb was attempted, and which rule blocked it.

That is IFC taint propagation in action. `sir run <agent>` adds an optional below-hook containment layer (macOS `sandbox-exec`, Linux `unshare --net`) for defense in depth, though it is still a measured preview.

## Hard limits

sir is v1 and experimental. The following tradeoffs are shipped deliberately.

- sir is strongest at the hook and tool boundary. It is not yet a complete host firewall. If a tool executor ignores the hook response, sir cannot stop the operation.
- MCP injection detection is roughly 50 regex patterns — an arms race by nature. Encoded, paraphrased, or non-English framing can evade literal matches. Tainted servers require re-approval as the mitigation.
- Turn boundaries use a 30-second gap heuristic and are gameable in theory.
- Shell classification is wrapper-aware and prefix-aware, not full POSIX semantics.
- Default lease allows push to origin, commit, loopback, and sub-agent delegation. Tighten with `sir trust`, `sir allow-host`, or managed policy.
- Model-internal reasoning and paraphrase are out of scope.
- Codex remains limited by the upstream Bash-only hook surface.
- If `mister-core` is missing from `PATH`, Go falls back to a deliberately restrictive subset of the policy. Parity tests enforce that the fallback is never more permissive than Rust.

## Day-to-day use

- Install once per machine with `sir install`. Use your agent normally.
- `sir log`, `sir explain --last`, `sir why`, and `sir doctor` are your investigation tools.
- `sir mcp` and `sir mcp wrap` inspect or harden command-based MCP servers.
- `sir unlock`, `sir allow-host`, `sir allow-remote`, and `sir trust` widen the lease — use them only when you intend to.

## Documentation

- Runtime behavior — [docs/user/runtime-security-overview.md](docs/user/runtime-security-overview.md)
- Agent integration — [Claude](docs/user/claude-code-hooks-integration.md) · [Gemini](docs/user/gemini-support.md) · [Codex](docs/user/codex-support.md)
- Contributor path — [CONTRIBUTING.md](CONTRIBUTING.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [docs/README.md](docs/README.md)
- Verification and evidence — [security-verification-guide.md](docs/research/security-verification-guide.md) · [validation-summary.md](docs/research/validation-summary.md) · [sir-threat-model.md](docs/research/sir-threat-model.md)
- FAQ — [docs/user/faq.md](docs/user/faq.md)

Report suspected vulnerabilities privately via [SECURITY.md](SECURITY.md). Licensed under the [Apache License, Version 2.0](LICENSE).
