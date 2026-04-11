# sir

sir is a security runtime for AI coding agents. It sits at the tool boundary for Claude Code, Gemini CLI, and Codex, tracks what the agent has touched, and blocks risky follow-on actions before they leave the machine.

## What it is

- Local enforcement, not a hosted security service
- Go CLI plus a zero-dependency Rust policy oracle
- Hook-mediated approvals, denials, tamper restore, and a hash-chained ledger

## Why use sir

- Agents can read secrets, call MCP servers, edit posture files, run shell, and push code in one session.
- Provider logs stop at governance. sir adds runtime enforcement and investigation where the action happens.
- The core policy path is deterministic and local. No daemon. No external dependency for normal enforcement.

## Supported agents

<!-- BEGIN GENERATED SUPPORT SUMMARY -->
- **Claude Code** — **Reference support.** Full 10-hook lifecycle with native interactive approval and complete tool-path coverage.
- **Gemini CLI** — **Near-parity support.** 6 hook events fire on Gemini CLI 0.36.0+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [docs/user/gemini-support.md](docs/user/gemini-support.md).
- **Codex** — **Limited support.** 5 hook events fire on `codex-cli` 0.118.0+ after enabling the `codex_hooks` feature flag (`codex features enable codex_hooks`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See [docs/user/codex-support.md](docs/user/codex-support.md).
<!-- END GENERATED SUPPORT SUMMARY -->

## Install in 3 minutes

Fastest path:

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

Run the baseline checks:

```bash
sir status
sir doctor
sir log verify
```

You want to see installed hooks, intact posture, and an intact ledger chain.

Then trigger one real protection path:

1. Ask the agent to read `.env`.
2. Approve it.
3. In the same turn, ask it to `curl https://httpbin.org/get`.
4. Run `sir explain --last`.

Expected result: sir asks before the read, blocks the external request, and records the causal chain.

## How to use it day to day

- Install once per machine with `sir install`.
- Use your agent normally. Reads, edits, tests, commits, and loopback traffic should stay quiet.
- Use `sir log`, `sir explain --last`, `sir why`, and `sir doctor` when you need investigation detail.
- Use `sir mcp` and `sir mcp wrap` to inspect or harden command-based MCP servers.
- Use `sir unlock`, `sir allow-host`, `sir allow-remote`, or `sir trust` only when you intentionally widen trust.

## Hard limits

- sir is strongest at the hook and tool boundary. It is not yet a complete host firewall.
- Shell classification is wrapper-aware and prefix-aware, not full shell semantics.
- Model-internal reasoning and paraphrase are out of scope.
- Codex remains limited by the current upstream Bash-only hook surface.
- `sir run <agent>` is a measured preview below hooks: `sir status` reports the launch mode, policy size, and blocked/allowed egress counts from the most recent contained run.

## Deeper docs

- Runtime behavior: [docs/user/runtime-security-overview.md](docs/user/runtime-security-overview.md)
- Claude / Gemini / Codex details: [docs/user/claude-code-hooks-integration.md](docs/user/claude-code-hooks-integration.md), [docs/user/gemini-support.md](docs/user/gemini-support.md), [docs/user/codex-support.md](docs/user/codex-support.md)
- Contributor path: [CONTRIBUTING.md](CONTRIBUTING.md), [ARCHITECTURE.md](ARCHITECTURE.md), [docs/README.md](docs/README.md)
- Verification and evidence: [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md), [docs/research/validation-summary.md](docs/research/validation-summary.md), [docs/research/sir-threat-model.md](docs/research/sir-threat-model.md)
