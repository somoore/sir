# Codex Support

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. Codex has **limited support** today because the upstream `codex-cli` hook surface is Bash-only: sir can mediate shell, but native tools (notably `apply_patch` writes and MCP calls) stay outside `PreToolUse`. If your Codex workflow is mostly shell, build, test, and git, you still get meaningful enforcement. If it leans heavily on native file writes or MCP tools, prefer Claude Code or Gemini CLI.

> **Note:** Minimum supported version is `0.118.0`. `sir doctor` warns on older versions.

<!-- BEGIN GENERATED SUPPORT DOC -->
## Status: limited support on codex-cli 0.118.0+ (Bash-only)

| Surface | Status | Notes |
|---|---|---|
| Hook events wired | ✅ 5 events | PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, Stop |
| Tool-path coverage | ⚠ Bash-only | Shell classification is enforced, but non-Bash tools bypass sir entirely. |
| Feature flag | ⚠ Required | Enable `codex_hooks` before any registered hooks can fire. |
| Interactive approvals | ❌ No | Codex folds sir's internal ask verdict into block with remediation text. |
| File-read IFC labeling | ✅ Yes | Bash-mediated sensitive reads (cat/sed/head/tail/grep/etc.) are promoted to read_ref before execution. |
| File-write pre-gating | ❌ No | Native apply_patch writes bypass PreToolUse on codex-cli 0.118.x; posture tamper is caught post-hoc. |
| Shell classification | ✅ Yes | Every hooked Codex tool call is Bash, so sir's shell classifier is the primary enforcement path. |
| MCP tool hooks | ❌ No | Codex does not fire hooks for MCP tools today. |
| Delegation gating | ❌ No | Codex exposes no SubagentStart-equivalent hook. |
| Config change detection | ❌ No | Codex exposes no ConfigChange-equivalent hook. |
| InstructionsLoaded scanning | ❌ No | Codex exposes no InstructionsLoaded-equivalent hook. |
| Elicitation interception | ❌ No | Codex exposes no Elicitation-equivalent hook. |
| Terminal posture sweep | ✅ Yes | The final posture sweep runs on Stop because Codex exposes no SessionEnd hook. |
<!-- END GENERATED SUPPORT DOC -->

## Required setup

Codex hooks do not fire until you enable the feature flag:

```bash
codex features enable codex_hooks
sir install --agent codex
sir doctor
```

Plain `sir install` also auto-detects Codex when it is already present on this machine.

sir writes `~/.codex/hooks.json` and may create or update `~/.codex/config.toml` to enable `codex_hooks` for you. In interactive mode it asks first; under `--yes` it enables the feature flag automatically.

## What works today

Codex is useful with sir when the workflow stays on the Bash path:

- External egress blocking.
- DNS and `sudo` classification.
- Package-install and posture sentinel checks.
- Bash-mediated sensitive reads such as `cat .env` or `sed -n ... .env`.
- Credential output scanning.

If your Codex session is mostly shell, build, test, and git, you still get meaningful enforcement.

## The important limitation

Codex does not currently expose a full-tool hook surface. Native non-Bash tools stay outside `PreToolUse`.

The biggest consequence is the `apply_patch` gap:

- sir cannot pre-gate native `apply_patch` writes.
- Posture drift is caught after the fact by sentinel hashing.
- The final posture sweep runs on `Stop` because Codex has no `SessionEnd`.

That is why Codex is documented as limited support, not near-parity.

## Other gaps

- No MCP argument or response hooks.
- No sub-agent delegation hook.
- No config-change hook.
- No instructions-loaded hook.
- No elicitation hook.

## Troubleshooting

- **`sir doctor` warns about `codex_hooks`:** run `codex features enable codex_hooks`.
- **`sir status` shows missing Codex hooks:** rerun `sir install --agent codex`.
- **A file write was not pre-gated:** confirm whether Codex used native `apply_patch` instead of a Bash write path.
