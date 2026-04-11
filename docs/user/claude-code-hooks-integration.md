# sir and Claude Code Hooks Integration

This page explains the reference-support path: how sir hooks into Claude Code, where the decisions are made, and how to debug the installation.

Other agents are narrower:

- sir also supports **Gemini CLI 0.36.0+ with near-parity support**. See [gemini-support.md](gemini-support.md).
- **Codex 0.118.0+ has limited support** on the current Bash-only hook path after enabling `codex_hooks`. See [codex-support.md](codex-support.md).

## Why Claude is the reference target

Claude Code exposes the richest hook surface sir supports today:

- `SessionStart`
- `UserPromptSubmit`
- `InstructionsLoaded`
- `PreToolUse`
- `PostToolUse`
- `SubagentStart`
- `ConfigChange`
- `Elicitation`
- `Stop`
- `SessionEnd`

That gives sir native interactive approval, full tool-path mediation, lifecycle-aware posture checks, and the cleanest investigation trail.

## What `sir install` writes

Claude hooks are configured in `~/.claude/settings.json`. `sir install` merges sir-managed hook entries into that file and uses the absolute path to the `sir` binary so PATH hijacking cannot replace the hook command.

If Claude, Gemini, and Codex coexist on the same machine, plain `sir install` auto-detects all supported agent surfaces that are already present. Use `sir install --agent claude` when you want to pin the install to Claude only.

The two primary enforcement hooks are:

- `sir guard evaluate` on `PreToolUse`
- `sir guard post-evaluate` on `PostToolUse`

The remaining handlers manage session initialization, turn boundaries, instruction-load logging, elicitation warnings, delegation gating, and the final sweep.

## Decision flow

1. Claude fires a hook with JSON on stdin.
2. `sir guard evaluate` normalizes the tool call into an intent.
3. `sir` adds session facts such as secret-session posture, pending install state, and trust labels.
4. `mister-core` returns `allow`, `deny`, or `ask`.
5. `sir` logs the decision and formats the result back into Claude's hook response shape.

`sir guard post-evaluate` then handles the after-the-fact checks:

- posture hashing and restore
- install sentinel verification
- MCP response injection scanning
- credential output scanning

## What to debug first

Run these in order:

```bash
sir status
sir doctor
sir explain --last
sir log
```

What they answer:

- `sir status`: are the Claude hooks installed?
- `sir doctor`: is the live hook subtree intact and does the ledger verify?
- `sir explain --last`: why did the last tool call get allowed, denied, or asked?
- `sir log`: what happened across the session?

## Manual spot check

You can test the hook handler directly:

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":".env"}}' | sir guard evaluate
```

That returns the JSON verdict sir would send back to Claude Code.

## Common failure modes

- `sir status` shows `NOT INSTALLED`: rerun `sir install`.
- `sir doctor` reports hook drift: doctor restores the sir-owned hook subtree from the canonical copy.
- A block looks wrong: inspect `sir explain --last` before changing policy. The usual cause is an earlier sensitive read or posture elevation, not a broken install.

**"sir: command not found" in hook execution**

Claude Code invokes the hook command in a shell. If `sir` is not on the PATH in that shell environment, the hook fails silently (fail-open). Ensure `~/.local/bin` is on your PATH in your shell profile, not just the current session.

**Hooks not firing**

Check that `~/.claude/settings.json` contains the sir entries:

```bash
cat ~/.claude/settings.json
```

If the file is missing or does not contain `sir guard`, re-run `sir install`.

**Everything is denied (deny-all)**

sir detected posture file tampering and locked the session. Run `sir doctor` to investigate and restore:

```bash
sir doctor
```

Then start a new Claude session.

---

## Coexistence with other hooks

sir's hooks can coexist with other hooks across all 10 hook events. Claude Code processes hooks in array order. sir's entries are merged into the existing `~/.claude/settings.json` hooks arrays; they do not replace existing entries.

If you have existing hooks, `sir install` adds sir's hooks to the arrays. `sir uninstall` removes only the entries whose `command` contains `sir guard`, leaving other hooks intact.

Example `~/.claude/settings.json` with sir and a custom hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "sir guard evaluate",
        "timeout": 5000
      },
      {
        "type": "command",
        "command": "my-custom-hook check",
        "timeout": 3000
      }
    ],
    "PostToolUse": [
      {
        "type": "command",
        "command": "sir guard post-evaluate",
        "timeout": 5000
      }
    ]
  }
}
```

**Important:** If another hook modifies `~/.claude/settings.json`, sir's PostToolUse handler will detect the hash mismatch and may trigger deny-all. Coordinate with other tools that modify hook configuration to avoid false positives. The safest approach is to install sir last, after all other hooks are configured.

---

## How sir returns verdicts to Claude Code

Claude Code expects a JSON object on stdout with at minimum a `decision` field. sir returns:

```json
{
  "decision": "allow"
}
```

```json
{
  "decision": "ask",
  "reason": "sir ASK  read .env\n  sensitivity: secret\n\n  Note: approving this will block external network requests for the\n  current turn to prevent accidental data leaks.\n  Details: sir explain --last"
}
```

```json
{
  "decision": "deny",
  "reason": "sir BLOCKED: network request to evil.example.com\n  Why: ..."
}
```

The `reason` field contains the human-readable message that Claude shows to the developer. As of v1.3, all messages follow the WHAT/WHY/HOW format: what happened (plain English), why (causal chain with timestamps), and how to fix it (specific commands). Every non-trivial message includes `sir explain --last` for full details.

For `ask` verdicts on sensitive file reads, sir includes a note in the reason explaining that approving will gate external network access for the current turn (by default), with instructions to run `sir unlock` if immediate clearance is needed.

All non-trivial messages follow the WHAT/WHY/HOW format: what happened (plain English), why (causal chain tracing back to the original secret read with timestamp), and how to fix it (specific commands). Every block and ask message includes `sir explain --last` for full details including IFC labels and recovery options.
