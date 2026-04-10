# Testing Rules

## Core Principle

Tests use the REAL evaluation path. No mock evaluators.

- Unit tests call production functions directly (e.g., `ScanMCPResponseForInjection`, `mapShellCommand`)
- Integration tests use `ExportEvaluatePayload` and `ExportPostEvaluatePayload` from `export_test_helpers.go`
- End-to-end tests create real files (`.env`, symlinks, `.aws/credentials`) in `t.TempDir()`

## Test File Locations

```
pkg/hooks/*_test.go                Unit tests per handler
pkg/hooks/parity_test.go           Go-vs-Rust delegation parity (PreToolUse + SubagentStart)
pkg/hooks/mcp_jailbreak_test.go    MCP injection pattern tests
pkg/hooks/toolmap_fuzz_test.go     Fuzz testing for shell classifier
pkg/hooks/credential_scan_test.go  Credential output scanning patterns + validators
pkg/session/session_test.go        Session state mutation + concurrency
pkg/lease/lease_test.go            Lease model + defaults
pkg/ledger/ledger_test.go          Ledger append, verify, hash chain, collision resistance
pkg/core/core_test.go              MSTR/1 encoding, TestLocalEvaluate_VerbParity
pkg/core/protocol_test.go          Protocol fault tolerance
pkg/telemetry/otlp_test.go         OTLP collector validation, hang resistance, redaction
cmd/sir/main_test.go               CLI command tests
tests/bypass_test.go               Multi-step attack sequences
tests/concurrency_test.go          Concurrent session + ledger
tests/install_test.go              Install/uninstall lifecycle
```

## Fixture Convention

Test fixtures in `testdata/hook-payloads/` named with expected verdict prefix:
- `allow-*.json` — expected allow
- `ask-*.json` — expected ask
- `deny-*.json` — expected deny/block
- `alert-*.json` — expected alert (posture/sentinel events)

Every "Must block / ask / allow / alert / edge case" fixture listed in `plan.md` must have a corresponding test.

## Required Tests for New Features

When adding a new verb:
1. Unit test in `toolmap_test.go` — classification correct
2. Add to fuzz seed corpus in `toolmap_fuzz_test.go`
3. Add a row to `TestLocalEvaluate_VerbParity` covering both secret and non-secret sessions
4. Parity test in `parity_test.go` if the verb has both Go and Rust policy paths

When adding a new hook handler:
1. Unit tests for the handler logic
2. Integration test via `ExportEvaluatePayload` or `ExportPostEvaluatePayload`
3. New fixture in `testdata/hook-payloads/`

When adding a new detection pattern:
1. Positive test (pattern fires on malicious input)
2. Negative test (pattern does NOT fire on benign input)
3. False positive test (common lookalikes that must not trigger)

## Concurrency Tests

Use goroutines + `sync.WaitGroup`. Run with `go test -race`.
- Session: concurrent Save, Load during Save, MarkSecretSession race, IncrementTurn race
- Ledger: concurrent Append, hash chain integrity, index monotonicity, no duplicate indices

## Rust Tests

- SHA-256: 11 NIST CAVS test vectors including the canonical 1M-`a` vector and 10 padding boundary cases (0/55/56/63/64/65/119/120/127/128 byte messages).
- JSON parser: trailing junk rejection, required field validation (`tool_name`, `verb`, `target`), unknown-field forward-compat pass-through.
- Zero external dependencies. Zero unsafe blocks. `cargo test --locked`.

## Parity Invariant

Two drift-catching tests in `pkg/core/`:

- `TestLocalEvaluate_VerbParity` (`core_test.go`) — table-driven, hand-maintained. If you add a verb that's more permissive in Go than in Rust, this test fails. When adding a new verb, add a row to the table — do not skip this step.
- `TestEnforcementGradientDocParity` (`doc_parity_test.go`) — treats the `## Enforcement Gradient` table in `.claude/rules/security.md` as an executable spec. Parses the markdown table and asserts each documented row against `localEvaluate` with "no more permissive than documented" semantics. Catches drift between docs and implementation in either direction.
