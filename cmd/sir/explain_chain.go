package main

import (
	"fmt"
	"path/filepath"

	"github.com/somoore/sir/pkg/ledger"
)

// buildCausalChain constructs a human-readable chain of events leading to the decision.
func buildCausalChain(entries []ledger.Entry, targetIndex int) []string {
	if targetIndex < 0 || targetIndex >= len(entries) {
		return nil
	}
	target := entries[targetIndex]

	if target.Decision == "allow" && target.Sensitivity != "secret" {
		return nil
	}

	var chain []string
	var secretEvents []ledger.Entry
	for i := 0; i < targetIndex; i++ {
		e := entries[i]
		if e.Sensitivity == "secret" && (e.Decision == "ask" || e.Decision == "allow") {
			secretEvents = append(secretEvents, e)
		}
		if e.Verb == "env_read" && (e.Decision == "ask" || e.Decision == "allow") {
			secretEvents = append(secretEvents, e)
		}
	}

	if len(secretEvents) > 0 {
		first := secretEvents[0]
		chain = append(chain, fmt.Sprintf("%s — Approved reading %s (entry #%d)",
			first.Timestamp.Format("15:04:05"),
			filepath.Base(first.Target),
			first.Index))
		chain = append(chain, fmt.Sprintf("%s — Session marked as carrying secret data",
			first.Timestamp.Format("15:04:05")))

		if len(secretEvents) > 1 {
			chain = append(chain, fmt.Sprintf("       ... %d additional secret file reads in this session",
				len(secretEvents)-1))
		}
	}

	ts := target.Timestamp.Format("15:04:05")
	chain = append(chain, fmt.Sprintf("%s — %s (entry #%d)",
		ts, verbHumanDescription(target.Verb, target.Target), target.Index))

	if target.Decision == "deny" && len(secretEvents) > 0 {
		chain = append(chain, fmt.Sprintf("%s — IFC check: secret session + %s = BLOCK",
			ts, sinkClassification(target.Verb)))
	} else if target.Decision == "deny" {
		chain = append(chain, fmt.Sprintf("%s — Policy rule: %s = BLOCK",
			ts, verbPolicyDescription(target.Verb)))
	}

	if target.Decision == "ask" && target.Sensitivity == "secret" {
		chain = append(chain, fmt.Sprintf("%s — File matched sensitive path pattern; approval required",
			ts))
	}

	return chain
}
