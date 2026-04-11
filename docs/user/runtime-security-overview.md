# Runtime Security Overview

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. Rather than jailing a process from below, it constrains the agent from above: intercepting tool calls at the hook layer, classifying intent, and deciding allow / ask / deny against a local policy oracle. Secret taint propagates through operations via information flow control (IFC), so reading `.env` in one step gates risky sinks in the next.

This page is the short operator-facing explanation of what sir catches, what it intentionally leaves alone, and how to verify the boundary on a fresh install. For the threat model and limitations, see [../research/sir-threat-model.md](../research/sir-threat-model.md).

## What sir catches

- Sensitive reads such as `.env`, `*.pem`, `*.key`, `.aws/*`, `.ssh/*`, `.netrc`, and similar credential-bearing paths.
- Secret-to-egress transitions. sir asks on the read, then blocks risky outbound sinks after the read is approved.
- Posture changes to files such as `CLAUDE.md`, `.mcp.json`, and the active agent hook config.
- Package-install tamper that mutates posture files or the install-time sentinel set.
- MCP credential leaks in tool arguments and prompt-injection markers in MCP responses where the host agent exposes MCP hooks.
- Structured credential output in normal tool responses, even when the source path itself was not labeled sensitive.

## What sir intentionally leaves quiet

sir's design rule is "quiet on normal coding, loud on dangerous transitions." Normal development should stay silent:

- Reading source files.
- Editing normal code.
- Running tests.
- `git commit`.
- Loopback requests such as `127.0.0.1` and `::1`.
- Glob, grep, list, and code-search operations.

## How the boundary is layered

1. The host agent fires a hook.
2. `sir` normalizes the tool call, classifies the intent, and adds session facts.
3. `mister-core` decides `allow`, `deny`, or `ask`.
4. `sir` records the decision in the ledger and performs post-tool checks such as posture hashing or MCP response scanning.

The optional below-hook layer is `sir run <agent>`:

- macOS uses localhost-only `sandbox-exec` plus a provider-aware local proxy with launch-time DNS pinning and exact-destination allowlisting.
- On macOS, host-only allowlist entries expand to exact destinations on `22`, `80`, and `443`; use `host:port` for non-standard ports. Loopback entries stay wildcarded.
- Linux uses `unshare --net` namespace mode with exact-destination egress allowlisting, durable-state protection, and fail-closed startup if the current-agent policy roots it must guard are missing.

That path is a measured preview, not the primary shipped boundary. Hook mediation is where sir is strongest today; `sir run` is experimental and exists to show the below-hook layer is plausible. `sir status` reports the last contained launch mode, the host/destination policy size, and the blocked/allowed egress counts recorded by the runtime layer.

## Known limitations

sir is v1 and experimental. Be aware of the tradeoffs before you rely on it:

- Hook-layer enforcement depends on the host agent honoring the hook response. If a tool executor ignores it, the operation proceeds.
- MCP injection detection is heuristic (~50 regex patterns). Tainted servers require re-approval as the mitigation; the detection itself is an arms race.
- Turn boundaries are detected via a 30-second gap heuristic and are gameable in theory.
- Shell classification is wrapper-aware and prefix-aware but not a full POSIX parser.
- The default lease is permissive (allows push_origin, commit, loopback, delegate) to reduce developer friction. Tighten with managed policy if you need more.
- If `mister-core` is absent from PATH, Go falls back to a deliberately restrictive subset of the policy, enforced by parity tests to never be more permissive than Rust.

## Fast verification

Run:

```bash
sir status
sir doctor
sir log verify
```

Then trigger one real protection path:

1. Ask the agent to read `.env`.
2. Approve it.
3. In the same turn, ask it to `curl https://httpbin.org/get`.
4. Run `sir explain --last`.

Expected result: the read is approved, the external request is blocked, and the ledger shows the causal chain.

## Go deeper

- [faq.md](faq.md)
- [claude-code-hooks-integration.md](claude-code-hooks-integration.md)
- [gemini-support.md](gemini-support.md)
- [codex-support.md](codex-support.md)
- [../research/sir-threat-model.md](../research/sir-threat-model.md)
