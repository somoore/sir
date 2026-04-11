# sir — Sandbox in Reverse

> A local security runtime for AI coding agents. Quiet on normal coding. Loud on dangerous transitions.

sir mediates tool calls at the hook layer, routes normalized facts into a zero-dependency Rust policy oracle, and records each verdict in a local hash-chained ledger. `sir run <agent>` adds optional OS containment on macOS and Linux, but that layer is still a measured preview.

## What it is

sir protects the transitions that matter: secret read to egress, posture tamper to deny-all plus restore, and untrusted MCP traffic to credential or injection scanning.

Supported agents:
<!-- BEGIN GENERATED SUPPORT SUMMARY -->
- **Claude Code** — **Reference support.** Full 10-hook lifecycle with native interactive approval and complete tool-path coverage.
- **Gemini CLI** — **Near-parity support.** 6 hook events fire on Gemini CLI 0.36.0+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [gemini-support.md](docs/user/gemini-support.md).
- **Codex** — **Limited support.** 5 hook events fire on `codex-cli` 0.118.0+ after enabling the `codex_hooks` feature flag (`codex features enable codex_hooks`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See [codex-support.md](docs/user/codex-support.md).
<!-- END GENERATED SUPPORT SUMMARY -->

## Why use sir

- Local and auditable: no daemon, no default phone-home path, and a ledger you can verify yourself with `sir log verify`.
- Quiet by default: reads, edits, tests, loopback traffic, and normal commits stay silent until the agent crosses a risky boundary.
- Security logic that composes: IFC carries secret reads into later writes, pushes, delegation, and external egress in the same session.

## Install in 3 minutes

```bash
curl -sSL https://raw.githubusercontent.com/somoore/sir/main/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent codex
```

Build from source:

```bash
# Requires [Rust 1.94.0+](https://rustup.rs/)
# Requires [Go 1.22+](https://go.dev/dl/) with toolchain auto-fetch to go1.25.9
make build
make install
```

Managed rollout uses `SIR_MANAGED_POLICY_PATH`. Runtime containment is available through `sir run <agent>` and is currently a measured preview, not the primary shipped boundary.

## Prove it works

```bash
sir status
sir doctor
sir log verify
```

1. Ask the agent to read `.env`.
2. Approve the prompt.
3. In the same turn, ask it to run `curl https://httpbin.org/get`.
4. Run `sir explain --last`.

Expected result: the read is asked, the external request is blocked, and the ledger shows the causal chain that linked them.

Useful day-to-day commands:

- `sir why`, `sir explain --last`, `sir log`
- `sir mcp`, `sir mcp wrap`
- `sir unlock`, `sir allow-host`, `sir allow-remote`, `sir trust`

## Hard limits

- Hook-layer mediation is the primary shipped boundary. If a host ignores hook responses, sir cannot stop the tool call.
- MCP injection detection is heuristic. Encoded, paraphrased, or non-English framing can evade literal matches.
- Shell classification is lexical, not a full POSIX parser.
- Turn boundaries use a 30-second gap heuristic.
- Codex remains limited by the current Bash-only upstream hook surface.
- If `mister-core` is missing, Go falls back to a stricter-but-smaller local policy path.

Docs: [runtime overview](docs/user/runtime-security-overview.md), [verification guide](docs/research/security-verification-guide.md), [threat model](docs/research/sir-threat-model.md), [FAQ](docs/user/faq.md), [contributor path](CONTRIBUTING.md), [architecture](ARCHITECTURE.md).

Security: report vulnerabilities privately via [SECURITY.md](SECURITY.md). Contributing: start with [CONTRIBUTING.md](CONTRIBUTING.md). License: [Apache-2.0](LICENSE).
