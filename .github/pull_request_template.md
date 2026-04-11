## Summary

- What changed?
- Why was it needed?

Linked issue / backlog track:

Did this create a follow-up `good-first-security-change`?

If contributor-facing behavior changed, which docs/issues were updated?

## Validation

- [ ] I ran the relevant tests or checks locally
- [ ] I ran `make contributor-check` from the PR branch
- [ ] I updated docs or comments if behavior changed
- [ ] I noted any follow-up work or known gaps below

Commands run:

```text
# paste commands here
```

## Security Impact

- Does this change affect policy evaluation, session state, IFC labeling, hook wiring, MCP handling, or install/doctor/status behavior?
- Does this change alter sir's documented security guarantees, support tiers, or runtime caveats?
- Does this add a new external dependency, privileged operation, or new place where secrets could be logged or persisted?
- If security-sensitive behavior changed, which fixtures/tests demonstrate the intended outcome?

## Risk and Rollout

- User-visible risks:
- Operator or maintainer follow-up:
- Rollback path:
