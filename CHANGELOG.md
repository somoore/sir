# Changelog

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir is experimental. Each release listed here is a snapshot of the "sandbox in reverse" model as it shipped, and entries are scoped to behavior users and contributors can actually observe.

This file tracks shipped releases only. Historical planning notes, launch copy, and exploratory findings live in git history rather than on the production repo surface.

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
