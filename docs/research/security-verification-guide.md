# sir Security Verification Guide

Use this guide when you need to verify a release artifact, validate a fresh
install, or rerun the highest-signal rollout checks.

Need the short evidence view first? Start with [Validation Summary](validation-summary.md).

## 1. Verify a release artifact

Prefer the repo-owned wrapper:

```bash
make verify-release RELEASE_TAG=vX.Y.Z
```

That script downloads the tagged release assets and verifies:

- cosign signatures on every archive
- the signed `checksums.txt`
- the signed `aibom.json`
- SLSA provenance for every archive
- `checksums.txt` against the downloaded archives
- the zero-ML declaration inside `aibom.json`

The canonical implementation is [scripts/verify-release.sh](../../scripts/verify-release.sh), and the same flow is exercised in the post-release smoke test inside [.github/workflows/release.yml](../../.github/workflows/release.yml).

### Manual fallback

If you need the low-level commands instead of the wrapper, keep these checks:

1. Verify the signed `checksums.txt`
2. Verify the archive signatures with cosign
3. Verify SLSA provenance for the exact tag

The wrapper script is the source of truth for the exact commands and expected
inputs.

## 2. Fresh-install verification

### Install and activate

```bash
cd /path/to/project
sir install            # auto-detect supported agents already on this machine
# or: sir install --agent codex
```

Expected result:

- sir previews the files it will create or modify
- the auto-detected or explicitly selected agent configs gain sir hook entries
- state is created under `~/.sir/projects/<hash>/`

### Verify operational surfaces

```bash
which sir && which mister-core
sir status
sir doctor
sir log verify
```

Expected result:

- binaries resolve from your PATH
- `sir status` reports `INSTALLED`
- `sir doctor` reports intact posture
- `sir log verify` reports an intact chain

### Verify MCP posture

```bash
sir mcp
```

Expected result:

- discovered MCP servers are listed
- command-based servers already rewritten by install show wrapped posture
- remaining raw command-based servers can be rewritten with `sir mcp wrap`

## 3. Core runtime checks

### Sensitive read then blocked egress

1. Ask the agent to read `.env`
2. Approve the read
3. In the same turn, ask it to `curl https://httpbin.org/get`

Expected result:

- the read is `ask`
- the external request is `deny`
- `sir explain --last` shows the causal chain

### Posture write prompt

Ask the agent to modify `CLAUDE.md`, `GEMINI.md`, or `.mcp.json`.

Expected result:

- sir prompts before the write
- the ledger records the decision

### Tamper restore

Modify the generated hook subtree in the supported agent config outside the
normal sir flow, then run:

```bash
sir doctor
```

Expected result:

- sir reports the tamper event
- managed installs restore from the managed manifest
- unmanaged installs restore the canonical sir-owned hook subtree

## 4. MCP-focused checks

### Credential leak in MCP arguments

Trigger an untrusted MCP request whose arguments contain a known credential
pattern.

Expected result:

- PreToolUse fires `mcp_credential_leak` for untrusted MCP servers
- the request is denied before it reaches the server
- trusted MCP servers bypass the credential scan, so the hook does not emit
  `mcp_credential_leak` for a trusted server
- if `SIR_LOG_TOOL_CONTENT=1`, `sir explain --last` shows redacted evidence

### Injection marker in MCP response

Trigger an MCP response that includes an injection marker near the start or end
of a large payload.

Expected result:

- PostToolUse catches it
- the ledger records the alert
- if evidence logging is enabled, the stored evidence includes the redacted
  head/tail window that tripped the detector

### Opaque MCP pivot still fails closed downstream

Trigger MCP output that leaks a known credential but phrases the follow-on
instruction in a form the literal scanner does not match directly, such as a
non-English sentence.

Expected result:

- PostToolUse still marks the session secret because of the credential output
- no broader prompt-scanner guarantee is implied by this check
- the next external egress attempt is denied
- the next Agent delegation attempt is denied

### MCP proxy caveats

- Claude Code is the reference-support target.
- Codex remains limited support with a **Bash-only** hook surface.
- macOS strict mode uses `sandbox-exec` for localhost-only egress.
- macOS `--allow-host` broadens to general outbound allow; `sandbox-exec`
  cannot scope egress per host.
- Linux `sir run --allow-host` uses exact-destination namespace rules, not a
  broad outbound allow.
- Linux host-specific egress exceptions are not currently supported through the
  MCP proxy path.

## 5. Contributor verification

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

- branch freshness check passes
- public-contract parity passes
- fixture replay passes
- benchmark budgets stay within tolerance
- Go and Rust tests are green

## 6. What to archive instead of keeping in the active repo

Do not grow the production docs surface with:

- launch posts
- GTM copy
- internal phase trackers
- one-off exploratory findings logs
- duplicate test-result narratives already represented in code, CI, or the validation summary
