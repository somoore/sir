# Extending sir with a New Agent Adapter

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

This guide is for contributors adding a new host-agent adapter under `pkg/agent/` or extending an existing one.

sir's core thesis — constrain the agent from above via hook mediation and a pure Rust policy oracle — only works if every supported host agent funnels its tool calls into the same normalized shape. Adapters are the translation layer that makes that possible.

Keep the scope narrow: adapters translate wire formats and declare capability metadata. They must not introduce new policy logic, because anything that influences allow / ask / deny belongs in `mister-core` or the shared hook pipeline, where the Go-never-looser-than-Rust invariant is enforceable.

## What belongs in the adapter layer

- Parse the host agent's hook payloads into sir's normalized `HookPayload`.
- Format sir verdicts back into the host agent's wire format.
- Declare the adapter's support surface in `AgentSpec`.
- Describe how sir installs and validates the host agent's hook config.

What does **not** belong here:

- New allow/deny policy rules in `mister-core`.
- New path-labeling or shell-classification logic in `pkg/hooks/`.
- One-off branching in `cmd/sir` for a single agent when typed spec data can express it.

## Minimum implementation checklist

1. **Add an `AgentSpec`** in `pkg/agent/<agent>.go`. Include identity, minimum version, capabilities, event and tool name translation, hook registrations, config strategy, and any feature-flag metadata.
2. **Add a thin adapter shim** that delegates to the shared helpers in `pkg/agent/base.go`. The normal shape is "spec + small wrapper"; avoid custom logic unless the wire format truly differs.
3. **Register the adapter** in [pkg/agent/agent.go](pkg/agent/agent.go).
4. **Add support fixtures** under `testdata/<agent>/`. At minimum, add `support.json` plus one real payload for each supported hook event.
5. **Add adapter-specific unit tests** in `pkg/agent/<agent>_test.go`.
6. **Run the shared conformance suite.** New adapters should pass `go test ./pkg/agent -run TestConformance`.

## Design constraints

- **Treat `AgentSpec` as the source of truth.** The adapter framework is intentionally data-heavy. Prefer adding typed spec fields over scattering new conditionals across install, status, or doctor flows.
- **Reuse the shared helpers** in `pkg/agent/base.go`. The codebase explicitly avoids Go embedding tricks. Custom behavior should go through narrow spec hooks such as extraction or lifecycle-format helpers.
- **Keep support claims machine-readable.** `AgentCapabilities`, support fixtures, and the support manifest must agree. Public docs and `sir status` consume that data.
- **Keep config handling declarative.** If the host config shape differs, express it through `ConfigStrategy` and hook registrations before reaching for command-specific branching.

## Files you will usually touch

- `pkg/agent/<agent>.go`
- `pkg/agent/<agent>_test.go`
- [pkg/agent/agent.go](pkg/agent/agent.go)
- [pkg/agent/spec.go](pkg/agent/spec.go)
- [pkg/agent/conformance_test.go](pkg/agent/conformance_test.go)
- `testdata/<agent>/support.json`
- `testdata/<agent>/*.json`

If the new adapter changes contributor-facing support claims, also update:

- [README.md](README.md)
- [docs/README.md](docs/README.md)
- Any agent-specific support page added under `docs/`

## Validation commands

Use the smallest validation set that matches your change:

```bash
go test ./pkg/agent ./cmd/sir
go test ./pkg/agent -run TestConformance
make replay
make public-contract
```

Use `make replay REPLAY_ARGS="--filter <pattern> --verbose"` to replay only the relevant hook-payload fixtures while iterating.

## Common pitfalls

- Forgetting to add the adapter to the registry, so `sir install` and `sir status` never see it.
- Updating prose docs without updating typed capability metadata.
- Adding agent-specific branching where `AgentSpec` or support fixtures should carry the difference.
- Extending adapter code when the change really belongs in the shared hook pipeline.

When in doubt, keep the adapter small and data-driven.
