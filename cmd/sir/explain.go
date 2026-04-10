package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
)

func cmdExplain(projectRoot string, index int) {
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	if len(entries) == 0 {
		fmt.Println("Ledger is empty. No decisions have been recorded yet.")
		return
	}

	if index < 0 {
		index = len(entries) - 1 // Default to last entry
	}
	if index >= len(entries) {
		fatal("index %d out of range (ledger has %d entries, valid range: 0-%d)", index, len(entries), len(entries)-1)
	}

	e := entries[index]

	// Section 1: Decision header
	fmt.Printf("Decision #%d: %s\n\n", e.Index, decisionTitle(e))

	// Section 2: Basic facts
	fmt.Printf("Timestamp: %s\n", e.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Tool:      %s\n", e.ToolName)
	fmt.Printf("Target:    %s\n", redactTargetIfSensitive(e.Verb, e.Target))
	fmt.Println()

	// Section 3: IFC Labels
	fmt.Println("IFC Labels:")
	sensitivity := e.Sensitivity
	if sensitivity == "" {
		sensitivity = "none"
	}
	trust := e.Trust
	if trust == "" {
		trust = "trusted"
	}
	provenance := e.Provenance
	if provenance == "" {
		provenance = "user"
	}

	// Add context to sensitivity label if inherited from a prior read
	sensitivityDetail := ""
	if sensitivity == "secret" {
		causal := ledger.FindCausalSecretRead(entries, index)
		if causal != nil && causal.Index != e.Index {
			sensitivityDetail = fmt.Sprintf(" (inherited from %s read at %s)",
				filepath.Base(causal.Target), causal.Timestamp.Format("15:04:05"))
		}
	}
	fmt.Printf("  Sensitivity: %s%s\n", sensitivity, sensitivityDetail)
	fmt.Printf("  Trust:       %s\n", trust)
	fmt.Printf("  Provenance:  %s\n", provenance)

	// Show sink classification for network/push verbs
	sink := sinkClassification(e.Verb)
	if sink != "" {
		fmt.Printf("  Sink:        %s\n", sink)
	}
	fmt.Println()

	// Section 4: Policy Rule
	fmt.Println("Policy Rule:")
	fmt.Printf("  Verb:   %s\n", e.Verb)
	fmt.Printf("  Rule:   %s\n", verbPolicyDescription(e.Verb))
	fmt.Printf("  Result: %s\n", strings.ToUpper(e.Decision))
	if e.Reason != "" {
		fmt.Printf("  Reason: %s\n", e.Reason)
	}
	fmt.Println()

	if e.Evidence != "" {
		fmt.Println("Evidence (redacted):")
		fmt.Println(indentExplainBlock(explainEvidencePreview(e.Evidence), "  "))
		fmt.Println()
	}

	// Section 5: Causal Chain (for deny/ask decisions, or any decision in a secret session)
	chain := buildCausalChain(entries, index)
	if len(chain) > 0 {
		fmt.Println("Causal Chain:")
		for i, step := range chain {
			fmt.Printf("  %d. %s\n", i+1, step)
		}
		fmt.Println()
	}

	// Section 6: Recovery Options (for deny/ask decisions)
	recovery := recoveryOptions(e)
	if len(recovery) > 0 {
		fmt.Println("Recovery Options:")
		for _, opt := range recovery {
			fmt.Printf("  %s\n", opt)
		}
		fmt.Println()
	}

	// Section 7: Alert details (for sentinel mutations, posture tamper, etc.)
	if e.AlertType != "" {
		fmt.Println("Alert Details:")
		fmt.Printf("  Type:     %s\n", e.AlertType)
		if e.Severity != "" {
			fmt.Printf("  Severity: %s\n", e.Severity)
		}
		if e.Agent != "" {
			fmt.Printf("  Agent:    %s\n", e.Agent)
		}
		if e.Restored {
			fmt.Printf("  Restored: yes\n")
		}
		if e.DiffSummary != "" {
			fmt.Printf("  Diff:     %s\n", e.DiffSummary)
		}
		fmt.Println()
	}

	// Section 8: Hash chain (for forensic verification)
	fmt.Println("Ledger Integrity:")
	fmt.Printf("  Entry Hash: %s\n", e.EntryHash[:16]+"...")
	fmt.Printf("  Prev Hash:  %s\n", e.PrevHash[:16]+"...")
}
