# First 30 Minutes

Use this path when you are new to the repo and want the shortest safe route to a useful change.

## 1. Start from clean main

```bash
git fetch origin
git switch -c my-change origin/main
make contributor-check
```

If `make contributor-check` fails, stop there. Fix the branch/worktree problem before you read diffs or change security code.

## 2. Read only two files first

- [Core Mental Model](core-mental-model.md): the trust boundaries and Go/Rust split in one short pass
- [CONTRIBUTING.md](../../CONTRIBUTING.md): the repo workflow and required verification commands

After that, read one subsystem file that matches the change you want to make.
If the change touches hook behavior, start with [pkg/hooks/doc.go](../../pkg/hooks/doc.go)
before you open the individual hook files.

## 3. Run the core verification loop

```bash
go test ./...
cargo test --locked
make replay
```

If you are touching hook evaluation, session state, ledger verification, or `sir explain`, also run:

```bash
make bench
```

## 4. Pick a safe entry point

| Change type | Start here | Why |
| --- | --- | --- |
| New shell command prefix or classifier fix | [pkg/hooks/toolmap.go](../../pkg/hooks/toolmap.go) and [pkg/hooks/toolmap_shell.go](../../pkg/hooks/toolmap_shell.go) | Tool intent mapping lives here |
| Sensitive-path or IFC-label update | [pkg/hooks/labels.go](../../pkg/hooks/labels.go) | Path-based labeling starts here |
| User-facing approval/block copy | [pkg/hooks/messages.go](../../pkg/hooks/messages.go) and siblings | Messaging is centralized here |
| Agent adapter change | [pkg/agent/](../../pkg/agent/) and [CONTRIBUTING-AGENTS.md](../../CONTRIBUTING-AGENTS.md) | Agent-specific hook behavior lives here |
| Policy-rule change | [mister-core/src/policy.rs](../../mister-core/src/policy.rs) and [pkg/policy/surface_gen.go](../../pkg/policy/surface_gen.go) | Rust decides policy; Go mirrors the typed surface |
| Session / lineage / posture state | [pkg/session/](../../pkg/session/) | Secret-session, managed-mode, and runtime state are here |
| Runtime containment | [cmd/sir/doc.go](../../cmd/sir/doc.go), [pkg/runtime/](../../pkg/runtime/), and [ARCHITECTURE.md](../../ARCHITECTURE.md) | Host-agent containment lives below the CLI in a reusable runtime package |

## 5. Choose a first change that stays bounded

Good first repo-local contributions:

- add or fix a shell classifier
- tighten a docs or public-contract guarantee
- add or improve a hook fixture
- improve a user-facing approval/block message
- add regression coverage around session, ledger, or explain behavior

Avoid these until you already understand the repo seams:

- changing the MSTR/1 protocol
- widening or narrowing policy behavior in Rust without adding tests
- changing managed-mode semantics
- changing runtime containment guarantees in docs without matching tests

## 6. Open the right supporting docs

- [Security Engineering Core](security-engineering-core.md)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [pkg/hooks package guide](../../pkg/hooks/doc.go)
- [CHANGELOG.md](../../CHANGELOG.md)
- [docs/README.md](../README.md)
