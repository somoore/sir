package main

import (
	"encoding/json"
	"os"

	"github.com/somoore/sir/pkg/friction"
	"github.com/somoore/sir/pkg/ledger"
)

// cmdFriction summarizes how much sir is interrupting normal work, from the
// project ledger. It is useful both after an observe-only rollout (where
// blocks are recorded without interrupting) and after enforcement is enabled.
func cmdFriction(projectRoot string, args []string) {
	asJSON := false
	for _, arg := range args {
		switch arg {
		case "--json":
			asJSON = true
		default:
			fatal("usage: sir friction [--json]")
		}
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	report := friction.Analyze(entries)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal("encode friction report: %v", err)
		}
		return
	}
	friction.Render(os.Stdout, report)
}
