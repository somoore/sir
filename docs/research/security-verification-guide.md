# sir Security Verification Guide

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir is an experimental security runtime for AI coding agents. Its core thesis is that the dangerous surface of an AI agent is not syscalls but *intents* — tool calls crossing from the model into the local machine — and that those intents can be mediated by hooks, classified through information flow control, and adjudicated by a Rust policy oracle before they execute.

Use this guide when you need to verify a release artifact, validate a fresh install, or rerun the highest-signal rollout checks against those claims. The checks here exercise the **real** evaluation path — the same hook handlers, the same `mister-core` verdicts, and the same ledger that run in production.

> **Tip:** Need the short evidence view first? Start with the [Validation Summary](validation-summary.md). If you are a researcher evaluating the threat model before running anything, start with the [sir Threat Model](sir-threat-model.md).

## 1. Verify a release artifact

Prefer the repo-owned wrapper:

```bash
make verify-release RELEASE_TAG=vX.Y.Z
```

That script downloads the tagged release assets and verifies:

- cosign signatures on every archive.
- The signed `checksums.txt`.
- The signed `aibom.json`.
- SLSA provenance for every archive.
- `checksums.txt` against the downloaded archives.
- The zero-ML declaration inside `aibom.json`.

The canonical implementation is [scripts/verify-release.sh](../../scripts/verify-release.sh), and the same flow is exercised in the post-release smoke test inside [.github/workflows/release.yml](../../.github/workflows/release.yml).

### Manual fallback

If you need the low-level commands instead of the wrapper, keep these checks:

1. Verify the signed `checksums.txt`.
2. Verify the archive signatures with cosign.
3. Verify SLSA provenance for the exact tag.

The wrapper script is the source of truth for the exact commands and expected inputs.

## 2. Fresh-install verification

### Install and activate

```bash
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent codex
```

Expected result:

- sir previews the files it will create or modify.
- The auto-detected or explicitly selected agent configs gain sir hook entries.
- State is created under `~/.sir/projects/<hash>/`.

### Verify operational surfaces

```bash
which sir && which mister-core
sir status
sir doctor
sir log verify
```

Expected result:

- Binaries resolve from your `PATH`.
- `sir status` reports `INSTALLED`.
- `sir doctor` reports intact posture.
- `sir log verify` reports an intact chain.

### Verify MCP posture

```bash
sir mcp
```

Expected result:

- Discovered MCP servers are listed.
- Command-based servers already rewritten by install show wrapped posture.
- Remaining raw command-based servers can be rewritten with `sir mcp wrap`.

## 3. Core runtime checks

### Sensitive read then blocked egress

1. Ask the agent to read `.env`.
2. Approve the read.
3. In the same turn, ask it to `curl https://httpbin.org/get`.

Expected result:

- The read is `ask`.
- The external request is `deny`.
- `sir explain --last` shows the causal chain.

### Posture write prompt

Ask the agent to modify `CLAUDE.md`, `GEMINI.md`, or `.mcp.json`.

Expected result:

- sir prompts before the write.
- The ledger records the decision.

### Tamper restore

Modify the generated hook subtree in the supported agent config outside the normal sir flow, then run:

```bash
sir doctor
```

Expected result:

- sir reports the tamper event.
- Managed installs restore from the managed manifest.
- Unmanaged installs restore the canonical sir-owned hook subtree.

## 4. MCP-focused checks

### Credential leak in MCP arguments

Trigger an untrusted MCP request whose arguments contain a known credential pattern.

Expected result:

- `PreToolUse` fires `mcp_credential_leak` for untrusted MCP servers.
- The request is denied before it reaches the server.
- trusted MCP servers bypass the credential scan, so the hook does not emit `mcp_credential_leak` for a trusted server.
- If `SIR_LOG_TOOL_CONTENT=1`, `sir explain --last` shows redacted evidence.

### Injection marker in MCP response

Trigger an MCP response that includes an injection marker near the start or end of a large payload.

Expected result:

- `PostToolUse` catches it.
- The ledger records the alert.
- If evidence logging is enabled, the stored evidence includes the redacted head/tail window that tripped the detector.

### Opaque MCP pivot still fails closed downstream

This check matters because MCP injection detection is **heuristic** (roughly 50 regex patterns). The load-bearing guarantee is not that every injection is caught at `PostToolUse` — it is that even when the literal scanner does not catch the framing, credential detection escalates the session and IFC blocks the follow-on exfiltration.

Trigger MCP output that leaks a known credential but phrases the follow-on instruction in a form the literal scanner does not match directly, such as a non-English sentence.

Expected result:

- `PostToolUse` still marks the session secret because of the credential output.
- No broader prompt-scanner guarantee is implied by this check.
- The next external egress attempt is denied.
- The next agent delegation attempt is denied.

> **Note:** If you can construct a sequence where credential material flows out without triggering either the literal scanner or the downstream IFC gate, that is a security bug and we want to see it.

### MCP proxy caveats

- Claude Code is the reference-support target.
- Codex remains limited support with a **Bash-only** hook surface.
- macOS strict mode uses `sandbox-exec` for localhost-only egress.
- macOS `--allow-host` broadens to general outbound allow; `sandbox-exec` cannot scope egress per host.
- Linux `sir run --allow-host` uses exact-destination namespace rules, not a broad outbound allow.
- Linux host-specific egress exceptions are not currently supported through the MCP proxy path.

## 5. Contributor and researcher verification

Run the production contributor checks before a release PR:

```bash
make contributor-check
make public-contract
make replay
make bench-check
go test ./...
cargo test --locked
```

Expected result:

- Branch freshness check passes.
- Public-contract parity passes.
- Fixture replay passes.
- Benchmark budgets stay within tolerance.
- Go and Rust tests are green.

Everything above runs against the production evaluation path. There are no mock evaluators in the test surface. If you are a researcher reproducing the validation summary, `go test ./... && cargo test --locked` is the minimum reproducible bar; `make replay` and `make public-contract` add the normalized fixture and contract coverage on top.

## 6. What to archive instead of keeping in the active repo

Do not grow the production docs surface with:

- Launch posts.
- GTM copy.
- Internal phase trackers.
- One-off exploratory findings logs.
- Duplicate test-result narratives already represented in code, CI, or the validation summary.
