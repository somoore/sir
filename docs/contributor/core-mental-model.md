# Core Mental Model

Read this before you open the long architecture docs.

## 1. sir starts from zero authority

The agent does not get to use the filesystem, shell, network, delegation, or
posture files because the host agent happens to expose those tools. It gets to
use them only when the current lease and runtime boundary allow them.

That is the core thesis behind "sandbox in reverse":

- start from no granted authority
- add only the authority the developer or lease explicitly grants
- treat everything else as deny or ask

## 2. The product has three enforcement layers

### Lease and policy

`mister-core` is the normalized policy oracle. It takes normalized facts and
returns `allow`, `deny`, or `ask`. It has no filesystem or network access.

Start here when you are changing:

- verb semantics
- IFC flow rules
- risk-tier behavior
- the allow/deny/ask gradient

Primary files:

- [mister-core/src/policy.rs](../../mister-core/src/policy.rs)
- [pkg/policy/surface_gen.go](../../pkg/policy/surface_gen.go)
- [pkg/core/](../../pkg/core/)

Go also enforces preflight and session-level gates when it can see facts Rust
cannot yet:

- deny-all after posture tamper
- credential detection in MCP arguments and responses
- pending-injection posture
- managed-mode command refusal

Those Go checks may narrow a Rust verdict. They must never widen a Rust deny
into `ask` or `allow`.

### Hook mediation

`pkg/hooks` is the fact collector and pre/post tool guardrail layer. It:

- parses host-agent hook payloads
- classifies tool calls into intents
- assigns IFC labels
- enforces session-fatal conditions around the tool path
- writes the ledger and emits telemetry

Start here when you are changing:

- shell or tool classification
- MCP argument/response checks
- posture tamper handling
- human-facing allow/deny/ask messages

Primary files:

- [pkg/hooks/doc.go](../../pkg/hooks/doc.go)
- [pkg/hooks/evaluate.go](../../pkg/hooks/evaluate.go)
- [pkg/hooks/toolmap.go](../../pkg/hooks/toolmap.go)

### Posture and managed restore

`pkg/posture` owns posture hashing, managed hook subtree drift detection, and
restore-only tamper repair.

Start here when you are changing:

- posture-file baseline hashing
- managed hook subtree comparison
- auto-restore behavior after hook tamper

Primary files:

- [pkg/posture/doc.go](../../pkg/posture/doc.go)
- [pkg/posture/](../../pkg/posture/)

### Host-agent containment

`pkg/runtime` is the layer below hooks. It tries to keep the host agent inside
an OS/runtime boundary even if the hook surface is incomplete.

Today that means:

- macOS: local proxy + `sandbox-exec`
- Linux: `unshare --net` containment with exact-destination egress allowlisting

Start here when you are changing:

- `sir run`
- proxy allowlists
- shadow-state seeding
- runtime containment status

Primary files:

- [pkg/runtime/](../../pkg/runtime/)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)

## 3. The Go layer may be stricter than Rust, never looser

Go can add additional restrictions from facts Rust cannot see yet, but it
exists to narrow authority, not to replace Rust as the policy oracle.

## 4. The main state objects are small and important

- lease: the authority contract
- session: mutable posture, secret-session, lineage, and runtime state
- ledger: append-only decision history

If you mutate any of those, add tests first.

## 5. The repo’s proof surface matters as much as the implementation

Before you trust a change, check the matching proof surface:

- unit and integration tests
- fixture replay in `testdata/`
- public-contract test
- benchmark budgets
- security invariant suite

If a change cannot be expressed in one of those, it is probably underspecified.
