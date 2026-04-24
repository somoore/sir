# Codex Support

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. Codex has **limited support** today: sir now registers Bash, native-write, MCP, and permission-request hooks where Codex exposes them, but lifecycle coverage remains narrower than Claude Code and upstream hook delivery is still the boundary. If your Codex workflow is mostly shell, build, test, native patching, git, and approved MCP calls, you get meaningful enforcement. If it needs full lifecycle coverage, prefer Claude Code.

> **Note:** Minimum supported version is `0.118.0`. `sir doctor` warns on older versions.

<!-- BEGIN GENERATED SUPPORT DOC -->
## Status: limited support on codex-cli 0.118.0+ (partial tool coverage)

| Surface | Status | Notes |
|---|---|---|
| Hook events wired | ✅ 6 events | PreToolUse, PermissionRequest, PostToolUse, UserPromptSubmit, SessionStart, Stop |
| Tool-path coverage | ⚠ Partial | Bash, native write, MCP, and permission-request hooks are registered where the host agent emits them; missing lifecycle hooks remain documented below. |
| Feature flag | ⚠ Required | Enable `codex_hooks` before any registered hooks can fire. |
| Interactive approvals | ❌ No | Codex folds sir's internal ask verdict into block with remediation text. |
| Permission-request broker | ✅ Yes | sir can broker agent-native permission request events through the same policy path. |
| File-read IFC labeling | ✅ Yes | Bash-mediated sensitive reads (cat/sed/head/tail/grep/etc.) are promoted to read_ref before execution. |
| File-write pre-gating | ✅ Yes | apply_patch/Edit/Write posture mutations are pre-gated when Codex emits their hooks; sentinel hashing remains the backstop. |
| Shell classification | ✅ Yes | Bash commands are classified for egress, DNS, persistence, sudo, and install risk. |
| MCP tool hooks | ✅ Yes | sir registers Codex MCP matchers and sees MCP arguments/responses when Codex emits mcp__* tool hooks. |
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

Codex is useful with sir when the workflow stays on covered tool paths:

- External egress blocking.
- DNS and `sudo` classification.
- Package-install and posture sentinel checks.
- Bash-mediated sensitive reads such as `cat .env` or `sed -n ... .env`.
- Native `apply_patch` / `Edit` / `Write` posture pre-gating when Codex emits those hooks.
- MCP argument and response scanning when Codex emits `mcp__*` tool hooks.
- Credential output scanning.

If your Codex session is mostly shell, patching, build, test, git, and approved MCP calls, you still get meaningful enforcement.

## The important limitation

Codex does not currently expose the full lifecycle hook surface Claude Code exposes. sir registers the tool hooks Codex makes available, but upstream hook delivery remains the boundary.

The biggest consequence is the lifecycle gap:

- sir has no Codex `SubagentStart`, `ConfigChange`, `InstructionsLoaded`, `SessionEnd`, or `Elicitation` equivalent.
- Posture drift is still caught by sentinel hashing.
- The final posture sweep runs on `Stop` because Codex has no `SessionEnd`.

That is why Codex is documented as limited support, not near-parity.

## Other gaps

- No sub-agent delegation hook.
- No config-change hook.
- No instructions-loaded hook.
- No elicitation hook.

## Troubleshooting

- **`sir doctor` warns about `codex_hooks`:** run `codex features enable codex_hooks`.
- **`sir status` shows missing Codex hooks:** rerun `sir install --agent codex`.
- **A file write was not pre-gated:** confirm the Codex version and whether the tool emitted `apply_patch`, `Edit`, or `Write` through the hook surface.
