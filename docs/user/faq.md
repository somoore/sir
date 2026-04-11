# sir Troubleshooting

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. It mediates tool calls at the hook layer and tracks secret taint via IFC, so a lot of its "blocks" are the intended design: you read a secret, and a later external sink is denied because the session is tainted. Use this page when sir is blocking something and you want the shortest path to the cause and the fix.

## First checks

```bash
sir status
sir doctor
sir log verify
sir explain --last
```

If those are healthy, sir itself is usually fine and the block is a real policy decision.

## Why is sir blocking `curl`?

This is the most common "false alarm" and it is actually sir working as intended. The current turn probably approved a sensitive read such as `.env`. sir asks on the read, then tracks the taint forward — the external `curl` in the same turn is blocked because the session is carrying secret data. That is IFC taint propagation, not a bug.

Typical fixes:

- Wait for the next turn boundary.
- Run `sir unlock`.
- Add the host with `sir allow-host <host>` if it is intentionally trusted.

## How do I clear the secret-session lock immediately?

```bash
sir unlock
```

That clears the active secret-session posture and records the action in the ledger.

## How do I check MCP posture?

```bash
sir mcp
sir mcp wrap
sir trust <server-name>
```

Use `sir mcp` to inventory servers, `sir mcp wrap` to harden raw command-based servers, and `sir trust` only for servers you control or have reviewed.

## What data does sir store?

By default, sir is local-only. State lives under `~/.sir/projects/<project-hash>/`. The ledger records paths, labels, hashes, and verdicts, not secret file contents.

If `SIR_OTLP_ENDPOINT` is set, sir can export verdict metadata to your own collector. Secret-labeled file paths are hashed before emission. Set `SIR_LOG_TOOL_CONTENT=1` only when you need redacted investigation evidence. Full attribute reference and SIEM query examples live in [siem-integration.md](siem-integration.md).

## What if sir detects posture tamper or starts failing closed?

Run:

```bash
sir doctor
```

Doctor verifies the hook config, lease, posture hashes, and ledger chain. If the local posture has drifted, doctor restores the sir-owned hook state from the canonical copy.

## How do I verify a published release?

Run:

```bash
make verify-release RELEASE_TAG=vX.Y.Z
```

That wrapper downloads the tagged release assets, verifies the signed checksums, validates provenance, and checks the signed `aibom.json`.

## Which agents are supported?

<!-- BEGIN GENERATED SUPPORT FAQ -->
Claude Code has **reference support**, Gemini CLI has **near-parity support**, and Codex has **limited support** today. `sir install` auto-detects the supported agents already present on this machine, or you can pin one with `sir install --agent <id>`:

- **Claude Code:** 10 hook events — reference support with native interactive approval, MCP scanning, delegation gating, config change detection, and elicitation coverage.
- **Gemini CLI 0.36.0+:** 6 hook events — near-parity support for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [gemini-support.md](gemini-support.md).
- **Codex 0.118.0+:** 5 hook events — limited support with a **Bash-only** upstream hook surface. Requires enabling `codex_hooks` (`codex features enable codex_hooks`). Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools still bypass PreToolUse; sir relies on PostToolUse sentinel hashing plus a final `Stop` sweep as the backstop. See [codex-support.md](codex-support.md).
<!-- END GENERATED SUPPORT FAQ -->

## Honest limits

sir is v1 and experimental. Be transparent with yourself about what it does and does not cover:

- sir is strongest at the hook and tool boundary. It is not a full host firewall and it cannot stop a tool executor that ignores the hook response.
- MCP injection detection is heuristic (~50 regex patterns). It is an arms race by nature; tainted servers require re-approval as the mitigation.
- Turn boundaries use a 30-second gap heuristic and are gameable in theory.
- Shell classification covers the common bypass patterns (wrappers, combined flags, compound commands) but is not a full POSIX parser.
- Codex remains limited by the current Bash-only upstream hook surface. Native `apply_patch` writes bypass `PreToolUse`.
- Model-internal paraphrase and arbitrary child-process behavior are out of scope.
- The default lease is intentionally permissive for developer friction; lock it down with managed policy if you need stricter defaults.
