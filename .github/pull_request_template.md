## Summary

- What changed?
- Why was it needed?

**Linked issue or backlog track:**

**Did this create a follow-up `good-first-security-change`?**

**If contributor-facing behavior changed, which docs or issues were updated?**

## Validation

- [ ] I ran the relevant tests or checks locally.
- [ ] I ran `make contributor-check` from the PR branch.
- [ ] I updated docs or comments if behavior changed.
- [ ] I noted any follow-up work or known gaps below.

Commands run:

```text
# paste commands here
> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

```

## Security Impact

sir has a small number of load-bearing safety rails. Please confirm this PR respects them:

- [ ] **Fail-closed on corrupted state.** Only `os.IsNotExist` seeds fresh defaults; any other error path returns `guardDeny`.
- [ ] **Go never widens Rust.** If this touches `pkg/core/core.go::localEvaluate` or adds a verb, Go is no more permissive than Rust for every row. `TestLocalEvaluate_VerbParity` and `TestEnforcementGradientDocParity` still pass.
- [ ] **No new dependencies in `mister-core` or `mister-shared`.** Both crates remain zero-dependency and zero-unsafe.
- [ ] **No raw secrets in ledger, telemetry, or logs.** Pattern names only, redacted evidence only.
- [ ] **Hook handlers return well-formed deny JSON on internal errors** rather than crashing or leaking partial state.

Then answer:

- Does this change affect policy evaluation, session state, IFC labeling, hook wiring, MCP handling, or install/doctor/status behavior?
- Does this change alter sir's documented security guarantees, support tiers, or runtime caveats? If yes, which docs were updated?
- Does this add a new external dependency, privileged operation, or new place where secrets could be logged or persisted?
- If security-sensitive behavior changed, which fixtures or tests demonstrate the intended outcome?
- If a new verb was added, did you add the corresponding row to `TestLocalEvaluate_VerbParity` and matching entries in `mister-shared/src/lib.rs` and `mister-core/src/policy.rs`?

## Risk and Rollout

- **User-visible risks:**
- **Operator or maintainer follow-up:**
- **Rollback path:**
