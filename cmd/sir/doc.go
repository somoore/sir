// Package main contains the sir CLI wiring and command-facing formatting.
//
// Contributor reading order:
//   - main.go: command dispatch and the public CLI surface.
//   - run.go plus status*.go: runtime containment, operator status, and the
//     thin CLI glue over pkg/runtime.
//   - mcp_command.go plus status_mcp.go: MCP command UX over pkg/mcp.
//   - install*.go: hook installation, merge, and restore-only managed mode.
//   - explain*.go and ledger_view.go: operator investigation surfaces.
//   - errors.go, managed_mode.go, allowlist.go, and doctor.go: recovery and
//     policy-widening workflows.
//
// Most reusable implementation now lives below the CLI in pkg/runtime,
// pkg/mcp, pkg/session, pkg/hooks, and pkg/core. Start here when a change is
// about flags, command behavior, or operator-facing output.
package main
