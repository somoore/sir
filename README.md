# sir — Sandbox in Reverse

sir is an experimental security runtime for AI coding agents (Claude Code, Gemini CLI, Codex). Traditional sandboxes constrain a process from below — syscalls, filesystem jails, namespaces. sir constrains the *agent* from above: it intercepts tool calls at the hook layer before they execute, decides allow/ask/deny against a local policy oracle, and writes every decision to an immutable hash-chained ledger.

## The thesis

AI coding agents are not a single sandboxable process. They orchestrate tools, spawn subprocesses, and call MCP servers. The dangerous surface is not syscalls — it is *intents* like "read `.env`, then curl an external host." sir uses information flow control (IFC) to track data sensitivity through operations: once an agent reads a secret file, that taint propagates to anything it writes, commits, or tries to push.

Design rule: quiet on normal coding, loud on dangerous transitions. Reads, edits, tests, commits, and loopback traffic stay silent. Only risky transitions — external network, secret egress, posture tampering, MCP injection — trigger prompts or denials.

## The problem sir solves

- AI coding agents routinely touch secrets (`.env`, cloud credentials, SSH keys) in the same session where they run shell and push code.
- MCP servers are a prompt-injection surface; there is no runtime check on what agents paste into them or what they exfiltrate through them.
- Provider logs stop at the governance layer. There is no local, tamper-evident audit trail of what the agent actually did on your machine.

sir addresses all three: intent mediation at the hook boundary, MCP argument and response scanning, and a hash-chained append-only ledger you can verify yourself.

## What it is

- Local enforcement, not a hosted security service. No daemon, no phone-home, no external dependency on the normal path.
- Go CLI (`sir`) plus a zero-dependency Rust policy oracle (`mister-core`). Go handles facts, session state, and the ledger; Rust decides policy.
- Hook-mediated allow / ask / deny decisions, tamper detection with restore, and a verifiable ledger.

## Honest limitations (sir is v1 and experimental)

- **Hook-layer, not OS-level.** If a tool executor ignores the hook response, sir cannot stop the operation. `sir run <agent>` adds an optional below-hook containment layer (macOS `sandbox-exec`, Linux `unshare --net`), but it is a measured preview, not the primary shipped boundary.
- **MCP injection detection is heuristic.** Roughly 50 regex patterns across four categories. An arms race by nature; tainted servers require re-approval as the mitigation.
- **Turn boundaries use a 30-second gap heuristic** and are gameable in theory.
- **Shell classification is lexical, not a full POSIX parser.** It covers the common bypass patterns (wrappers, combined flags, compound commands) but cannot cover every trick.
- **Default lease is developer-friendly.** Push to origin, commit, loopback, and sub-agent delegation are allowed out of the box; tighten with `sir trust`, `sir allow-host`, and managed policy if you want more.
- **If `mister-core` is not on PATH**, Go falls back to a deliberately restrictive subset of the policy. The fallback is enforced by parity tests to never be more permissive than Rust.

## Supported agents

<!-- BEGIN GENERATED SUPPORT SUMMARY -->
- **Claude Code** — **Reference support.** Full 10-hook lifecycle with native interactive approval and complete tool-path coverage.
- **Gemini CLI** — **Near-parity support.** 6 hook events fire on Gemini CLI 0.36.0+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [gemini-support.md](docs/user/gemini-support.md).
- **Codex** — **Limited support.** 5 hook events fire on `codex-cli` 0.118.0+ after enabling the `codex_hooks` feature flag (`codex features enable codex_hooks`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See [codex-support.md](docs/user/codex-support.md).
<!-- END GENERATED SUPPORT SUMMARY -->

## Quickstart (3 minutes)

The fastest path is `install.sh`. It drops the `sir` binary into `~/.local/bin`, preserves any existing `~/.sir/` state, and is the only supported update path — there is no self-updater.

```bash
curl -sSL https://raw.githubusercontent.com/somoore/sir/main/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent codex
```

Build from source if you prefer:

Requires [Rust 1.94.0+](https://rustup.rs/) and [Go 1.22+](https://go.dev/dl/) with toolchain auto-fetch to `go1.25.9`.

```bash
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

## What to expect on first run

After `sir install`, launch your agent as usual. You should not notice sir during normal development — that is the point. Reads, edits, tests, commits, and loopback requests stay silent.

Baseline health checks:

```bash
sir status       # hooks installed, session posture, last contained-run info
sir doctor       # hook subtree intact, ledger chain verifies, sentinels unchanged
sir log verify   # walk the hash chain and report first corruption, if any
```

You want to see installed hooks, intact posture, and an intact ledger chain.

Then trigger one real protection path to prove the boundary:

1. Ask the agent to read `.env`.
2. Approve the prompt. sir labels the read as secret and marks the session tainted.
3. In the same turn, ask it to `curl https://httpbin.org/get`.
4. Run `sir explain --last`.

Expected result: sir asks before the read, blocks the external request, and records the full causal chain in the ledger. That is IFC taint propagation in action.

## Day-to-day use

- Install once per machine with `sir install`. Use your agent normally.
- `sir log`, `sir explain --last`, `sir why`, and `sir doctor` are your investigation tools when something gets blocked or asked.
- `sir mcp` and `sir mcp wrap` inspect or harden command-based MCP servers.
- `sir unlock`, `sir allow-host`, `sir allow-remote`, and `sir trust` are the trust-widening commands — use them only when you intend to grant something.

## Who this is for

- **Developers:** you want a quiet local guard that catches the obvious failure modes (secret egress, posture tampering, MCP injection) without slowing down normal coding, and that gives you an audit trail if something looks wrong later.
- **Researchers:** the threat model is documented in [docs/research/sir-threat-model.md](docs/research/sir-threat-model.md). The policy oracle is a small, zero-dependency Rust crate with hand-maintained parity tests against the Go fallback. The ledger is hash-chained and length-prefix-encoded (v2.1), so collision attacks on the delimiter are in scope.
- **Contributors:** see [CONTRIBUTING.md](CONTRIBUTING.md) and [ARCHITECTURE.md](ARCHITECTURE.md). Go stays standard-library-only; `mister-core` stays zero-dependency and zero-unsafe. The fastest orientation is [docs/contributor/first-30-minutes.md](docs/contributor/first-30-minutes.md).

## Deeper docs

- Runtime behavior: [docs/user/runtime-security-overview.md](docs/user/runtime-security-overview.md)
- Claude / Gemini / Codex details: [docs/user/claude-code-hooks-integration.md](docs/user/claude-code-hooks-integration.md), [docs/user/gemini-support.md](docs/user/gemini-support.md), [docs/user/codex-support.md](docs/user/codex-support.md)
- Contributor path: [CONTRIBUTING.md](CONTRIBUTING.md), [ARCHITECTURE.md](ARCHITECTURE.md), [docs/README.md](docs/README.md)
- Verification and evidence: [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md), [docs/research/validation-summary.md](docs/research/validation-summary.md), [docs/research/sir-threat-model.md](docs/research/sir-threat-model.md)
