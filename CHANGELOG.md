# Changelog

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir is experimental. Each release listed here is a snapshot of the "sandbox in reverse" model as it shipped, and entries are scoped to behavior users and contributors can actually observe.

This file tracks shipped releases only. Historical planning notes, launch copy, and exploratory findings live in git history rather than on the production repo surface.

## v0.0.5 — 2026-04-14 — approval-friction reduction and MCP recovery fixes

**Approval-friction reduction**

- Fixed the Hopper / MCP prompt storm path that could ask on nearly every tool call after a single false-positive taint event. Elevated posture no longer degrades ordinary local `Bash`, `Edit`, `Write`, or task-management work into repeated approval prompts.
- Approved MCP calls are no longer gated just because the session once carried credentials. Approved MCP calls are still gated when they touch inputs that already carry secret lineage.
- Tainted MCP servers now ask once per taint event instead of on every call forever. After the developer continues once and the next response from that server is clean, follow-on calls stop prompting until a fresh suspicious response appears.

**False-positive fixes**

- Refined MCP injection detection so Hopper-style string-search output containing phrases like `override safety` no longer counts as prompt injection unless it appears in directive context.
- Refined `high_entropy_token` detection so bare high-entropy technical text does not mark the session secret unless nearby credential-like context is present.

**Recovery and operator UX**

- `sir unlock` now clears the full transient runtime restriction set, not just `secret_session`. This clears stale prompt-driving MCP taint and elevated posture as well as secret-session locks.
- `sir status` now surfaces transient taint state directly, including elevated posture, tainted MCP servers, and pending alert state, so approval behavior is visible instead of opaque.
- `sir doctor`, recovery hints, and session-cleared messaging now describe transient runtime restrictions accurately instead of referring only to the old secret-session lock model.

## v0.0.4 — 2026-04-13 — subagent false-positive fix and MCP lease refresh

**Subagent false-positive fix**

- Fixed `high_entropy_token` false positives that were re-marking sessions secret on path-heavy Bash output and reproduced research-document reads. This was the recurring root cause behind normal Claude subagent launches being blocked even after `sir unlock`.
- Verified against the reproduced `apfelbauer` cases: the path-heavy Bash output no longer taints the session, the `VULN-02` read no longer taints the session, and a follow-on `SubagentStart` for a write-capable worker is allowed as a clean session.

**MCP approval drift**

- `approved_mcp_servers` now refreshes from discovered unmanaged MCP config on hook load, so legitimate project MCP servers stop prompting as "unknown" after lease drift or post-install MCP changes.
- The MCP approval guidance now points to refreshing approvals via MCP config plus `sir install`, rather than incorrectly suggesting `sir trust <server>` for this path.

**Operator ergonomics**

- `sir doctor` no longer claims the session is normal while a secret-session lock is still active.
- The public-contract parity test now treats ignored local workspace files as untracked-only, so developer-local `.claude/settings.local.json` state does not make `./cmd/sir` fail.

## v0.0.3 — 2026-04-12 — supply chain hardening and false positive fix

**Binary integrity verification**

- `sir verify` — on-demand binary integrity check against install-time manifest.
- mister-core is hash-verified before first execution per process. Tampered oracle triggers hard deny on all tool calls.
- Both `install.sh` and `download.sh` write `~/.sir/binary-manifest.json` with SHA-256 hashes at install time.
- Sentinel file detects manifest deletion as tamper (fail closed).
- `download.sh` verifies cosign signatures on `checksums.txt` when cosign is available.

**High-entropy scanner false positive fix**

- Fixed `high_entropy_token` credential scanner falsely triggering on JSON-wrapped tool output, markdown badge URLs, and structured text. This caused spurious secret-session activation that blocked all subagent delegation during normal coding — the root cause of the "sir blocks subagents" usability bug.
- Named credential patterns (AWS keys, GitHub PATs, OpenAI keys, etc.) are unaffected and still detect credentials inside any wrapper format.

**Other changes**

- `sir version --check` now shows changelog, checksums link, and copy-paste update commands when a newer release exists. Fixed prerelease version detection.
- `aibom.json` SLSA level corrected from 3 to 0 (provenance job deferred pending upstream fix).
- SECURITY.md rewritten with GitHub issue disclosure template.
- CODE_OF_CONDUCT.md updated to use GitHub issues for reporting.
- Fixed false `go.sum` claim in SECURITY.md (zero Go deps = no go.sum).

## v0.0.1 — 2026-04-11 — pre-alpha, first public release

This is the first tagged public release of sir. The project is **pre-alpha**: the core "sandbox in reverse" model ships end to end, but the threat model is narrow, several detections are heuristic, and the public API (both CLI and policy verbs) is expected to change without notice. Do not deploy on production infrastructure.

**What ships**

- **Hook-mediated intent enforcement** across Claude Code (reference support, 10 hooks), Gemini CLI (near-parity, 6 hooks), and Codex (limited, 5 hooks, Bash-only surface).
- **Zero-dependency Rust policy oracle** (`mister-core`) with hand-maintained parity tests against a restrictive Go fallback.
- **Information flow control** labeling on sensitive reads; taint propagation into writes, commits, pushes, and delegation in the same session.
- **MCP defense**: credential-leak scanning on arguments (runs regardless of secret-session state), injection scanning on responses with server tainting, elicitation harvest detection, and an MCP proxy path.
- **Posture tamper detection** on `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/settings.json`, and in-repo posture files, with auto-restore from a canonical copy and session-fatal deny-all on tamper.
- **Hash-chained append-only ledger** (v2.1 length-prefixed encoding, SHA-256) with `sir log verify` and per-entry redaction.
- **Optional below-hook containment** via `sir run <agent>` — macOS `sandbox-exec` proxy, Linux `unshare --net` namespace. Measured preview, not the primary shipped boundary.
- **Operator surface**: `sir status`, `sir doctor`, `sir explain`, `sir why`, `sir log`, `sir audit`, `sir trace`, `sir mcp`, `sir unlock`, `sir allow-host`, `sir allow-remote`, `sir trust`.
- **Install and update discipline**: `install.sh` is idempotent and the only supported update path, with a downgrade guard gated on `SIR_ALLOW_DOWNGRADE=1`. `rustup-init` is pinned by SHA-256 across Linux x86_64, Linux arm64, macOS x86_64, and macOS arm64.
- **Release trust**: reproducible-build verification, signed artifacts via Sigstore cosign (keyless OIDC), CycloneDX and SPDX SBOMs, and an AIBOM zero-ML declaration. SLSA provenance is wired but deferred pending an upstream `slsa-github-generator` fix.
- **CI hygiene**: GitHub Actions pinned by commit SHA, least-privilege permissions, `persist-credentials: false`, CodeQL Go SAST on every PR and push, gosec on every PR and every main commit, `cargo-deny`, `govulncheck`, reproducible-build diff check, OpenSSF Scorecard workflow, and zizmor Actions linting.

**Known limitations**

- MCP injection detection is a ~50-pattern regex set and is inherently an arms race. Tainted servers require re-approval as the mitigation.
- Turn boundaries use a 30-second gap heuristic and are gameable in theory.
- Shell classification is wrapper-aware and prefix-aware, not a full POSIX parser.
- The default lease allows push to origin, commit, loopback, and sub-agent delegation out of the box. Tighten with `sir trust`, `sir allow-host`, or managed policy.
- `sir run <agent>` containment is a measured preview, not a complete host firewall.
- Single-maintainer tradeoffs are documented in `docs/contributor/supply-chain-policy.md` (Scorecard Code-Review, Branch-Protection, and CII-Best-Practices 0/10 are accepted until a second trusted reviewer exists and the bestpractices.dev self-assessment is complete).

**For operators**

- Install: `curl -sSL https://raw.githubusercontent.com/somoore/sir/main/install.sh | bash` then `sir install`
- Verify: `sir status && sir doctor && sir log verify`
- Uninstall: `sir uninstall` (state preserved at `~/.sir/` for forensic review)

See [README.md](README.md) for the full quickstart and limitations, [ARCHITECTURE.md](ARCHITECTURE.md) for the Go + Rust split, [docs/research/sir-threat-model.md](docs/research/sir-threat-model.md) for the threat model, and [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md) for the verification path.
