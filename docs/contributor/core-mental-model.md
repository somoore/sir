# Core Mental Model

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

Read this before you open the long architecture docs. It is the shortest honest description of what sir is and what it is not.

## 0. What problem sir solves

AI coding agents (Claude Code, Codex, Gemini CLI) do not run as a single sandboxable process. They orchestrate tools, spawn subprocesses, and call MCP servers, and the thing you actually want to block is not a syscall — it is an *intent* like "read `.env`, then curl a host I have never seen." Traditional sandboxes cannot express that; they constrain the process from below. sir constrains the agent from above, at the hook layer where intents are still legible.

> **Note:** sir is experimental. It ships with known v1 tradeoffs (lexical shell classification, heuristic MCP injection detection, a permissive default lease). Read this doc so you know which guarantees are hard and which are heuristic.

## 1. sir starts from zero authority

The agent does not get to use the filesystem, shell, network, delegation, or posture files because the host agent happens to expose those tools. It gets to use them only when the current lease and runtime boundary allow them.

That is the core thesis behind "sandbox in reverse":

- Start from no granted authority.
- Add only the authority the developer or lease explicitly grants.
- Treat everything else as deny or ask.
- Propagate IFC taint across operations, so a secret read contaminates downstream writes, commits, and pushes.

## 2. The product has three enforcement layers

### Lease and policy

`mister-core` is the normalized policy oracle. It takes normalized facts and returns `allow`, `deny`, or `ask`. It has no filesystem or network access.

Start here when you are changing:

- Verb semantics.
- IFC flow rules.
- Risk-tier behavior.
- The allow / deny / ask gradient.

Primary files:

- [mister-core/src/policy.rs](../../mister-core/src/policy.rs)
- [pkg/policy/surface_gen.go](../../pkg/policy/surface_gen.go)
- [pkg/core/](../../pkg/core/)

Go also enforces preflight and session-level gates when it can see facts Rust cannot yet:

- Deny-all after posture tamper.
- Credential detection in MCP arguments and responses.
- Pending-injection posture.
- Managed-mode command refusal.

These Go checks may narrow a Rust verdict. They must never widen a Rust deny into `ask` or `allow`.

### Hook mediation

`pkg/hooks` is the fact collector and pre/post-tool guardrail layer. It:

- Parses host-agent hook payloads.
- Classifies tool calls into intents.
- Assigns IFC labels.
- Enforces session-fatal conditions around the tool path.
- Writes the ledger and emits telemetry.

Start here when you are changing:

- Shell or tool classification.
- MCP argument and response checks.
- Posture tamper handling.
- Human-facing allow / deny / ask messages.

Primary files:

- [pkg/hooks/doc.go](../../pkg/hooks/doc.go)
- [pkg/hooks/evaluate.go](../../pkg/hooks/evaluate.go)
- [pkg/hooks/toolmap.go](../../pkg/hooks/toolmap.go)

### Posture and managed restore

`pkg/posture` owns posture hashing, managed hook subtree drift detection, and restore-only tamper repair.

Start here when you are changing:

- Posture-file baseline hashing.
- Managed hook subtree comparison.
- Auto-restore behavior after hook tamper.

Primary files:

- [pkg/posture/doc.go](../../pkg/posture/doc.go)
- [pkg/posture/](../../pkg/posture/)

### Host-agent containment

`pkg/runtime` is the layer below hooks. It tries to keep the host agent inside an OS/runtime boundary even if the hook surface is incomplete.

Today that means:

- **macOS** — local proxy plus `sandbox-exec`.
- **Linux** — `unshare --net` containment with exact-destination egress allowlisting.

Start here when you are changing:

- `sir run`.
- Proxy allowlists.
- Shadow-state seeding.
- Runtime containment status.

Primary files:

- [pkg/runtime/](../../pkg/runtime/)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)

## 3. The Go layer may be stricter than Rust, never looser

Go can add additional restrictions from facts Rust cannot see yet, but it exists to narrow authority, not to replace Rust as the policy oracle. This is the one invariant that keeps the policy surface reviewable: if you want to know the upper bound of what sir will allow, you only have to read `mister-core`. Parity is machine-checked by `TestLocalEvaluate_VerbParity` and `TestEnforcementGradientDocParity`.

## 4. The main state objects are small and important

- **Lease** — the authority contract.
- **Session** — mutable posture, secret-session, lineage, and runtime state.
- **Ledger** — append-only decision history.

If you mutate any of those, add tests first.

## 5. The repo's proof surface matters as much as the implementation

Before you trust a change, check the matching proof surface:

- Unit and integration tests.
- Fixture replay in `testdata/`.
- Public-contract tests.
- Benchmark budgets.
- Security invariant suite.

If a change cannot be expressed in one of those, it is probably underspecified.
