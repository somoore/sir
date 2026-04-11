# Gemini CLI Support

**Minimum supported version: 0.36.0** (`sir doctor` warns on older versions).

<!-- BEGIN GENERATED SUPPORT DOC -->
## Status: near-parity support on Gemini CLI 0.36.0+

| Surface | Status | Notes |
|---|---|---|
| Hook events wired | ✅ 6 events | BeforeTool, AfterTool, BeforeAgent, SessionStart, SessionEnd, AfterAgent |
| Tool-path coverage | ✅ Full | File IFC labeling, shell classification, MCP scanning, and credential output scanning all run on the hooked tool path. |
| Interactive approvals | ❌ No | Gemini CLI folds sir's internal ask verdict into deny with remediation text. |
| File-read IFC labeling | ✅ Yes | BeforeTool labels read_file/read_many_files before execution. |
| File-write pre-gating | ✅ Yes | BeforeTool gates write_file / replace posture mutations before execution. |
| Shell classification | ✅ Yes | Bash commands are classified for egress, DNS, persistence, sudo, and install risk. |
| MCP tool hooks | ✅ Yes | sir sees both MCP arguments and MCP responses on this agent. |
| Delegation gating | ❌ No | Gemini CLI exposes no SubagentStart-equivalent hook. |
| Config change detection | ❌ No | Gemini CLI exposes no ConfigChange-equivalent hook. |
| InstructionsLoaded scanning | ❌ No | Gemini CLI exposes no InstructionsLoaded-equivalent hook. |
| Elicitation interception | ❌ No | Gemini CLI exposes no Elicitation-equivalent hook. |
| Terminal posture sweep | ✅ Yes | SessionEnd closes single-turn blind spots with one last sentinel sweep. |
<!-- END GENERATED SUPPORT DOC -->

## What works well

Gemini fires hooks for the normal tool path, not just Bash. That means sir can apply the same core protections it uses on Claude Code for:

- file-read IFC labeling
- posture-file pre-gating
- shell classification
- MCP argument and response scanning
- credential output scanning

If your workflow is primarily Read, Write, Edit, Bash, and MCP tools, Gemini is close to Claude in day-to-day value.

## What is missing

Gemini does not expose the lifecycle hooks sir would need for:

- sub-agent delegation gating
- immediate config-change detection
- instruction-load scanning
- elicitation interception

If those gaps matter for your workflow, prefer Claude Code.

## Install and verify

```bash
sir install            # auto-detects Gemini when it is present
# or:
sir install --agent gemini
sir status
sir doctor
```

The live config is `~/.gemini/settings.json`. sir keeps a canonical backup of the sir-owned hooks subtree at `~/.sir/hooks-canonical-gemini.json`.

## Operational notes

- Gemini has no native `ask` verdict, so sir converts internal `ask` decisions into deny-with-remediation text.
- Gemini hook timeouts are milliseconds, so the generated config uses `10000` for tool hooks and `5000` for session hooks.
- The shell classifier, labeler, and policy oracle are shared across agents. If a classification bug is fixed once, Gemini gets the same fix.

## Troubleshooting

- `sir install --agent gemini` says Gemini was not detected: make sure `~/.gemini/` or a `gemini` binary exists.
- `sir status` shows missing Gemini hooks: rerun install and inspect `~/.gemini/settings.json`.
- A tool call looked wrong: run `sir explain --last` and verify the tool name and target were normalized as expected.
