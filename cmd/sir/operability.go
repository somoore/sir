package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/telemetry"
)

const (
	ledgerWarnBytes         int64 = 10 * 1024 * 1024
	ledgerWarnEntries             = 10000
	lineageWarnDerivedPaths       = 256
)

type operabilitySnapshot struct {
	Telemetry   *telemetry.Health
	LedgerSize  int64
	LedgerWarn  bool
	LineageLive int
	LineageSize int
	LineageWarn bool
}

func inspectOperability(projectRoot string, state *session.State, ledgerCount int) operabilitySnapshot {
	health, _ := telemetry.LoadHealth(projectRoot)

	var ledgerSize int64
	if fi, err := os.Stat(ledger.LedgerPath(projectRoot)); err == nil {
		ledgerSize = fi.Size()
	}

	snap := operabilitySnapshot{
		Telemetry:  health,
		LedgerSize: ledgerSize,
		LedgerWarn: ledgerSize >= ledgerWarnBytes || ledgerCount >= ledgerWarnEntries,
	}
	if state != nil {
		snap.LineageLive = len(state.ActiveEvidence)
		snap.LineageSize = len(state.DerivedPaths())
		snap.LineageWarn = snap.LineageSize >= lineageWarnDerivedPaths
	}
	return snap
}

func printStatusOperability(snapshot operabilitySnapshot) {
	if snapshot.Telemetry == nil || !snapshot.Telemetry.EndpointConfigured {
		fmt.Printf("  %-9s off\n", "telemetry")
	} else {
		fmt.Printf(
			"  %-9s on (queue %d x %d, queued %d, dropped %d)\n",
			"telemetry",
			snapshot.Telemetry.QueueSize,
			snapshot.Telemetry.WorkerCount,
			snapshot.Telemetry.QueuedCount,
			snapshot.Telemetry.DroppedCount,
		)
		if snapshot.Telemetry.DroppedCount > 0 {
			fmt.Printf("             Warning: telemetry dropped %d event(s); collector backpressure is now visible in-product.\n", snapshot.Telemetry.DroppedCount)
			fmt.Printf("             Fix: check the OTLP collector or unset SIR_OTLP_ENDPOINT if you need to disable export.\n")
		}
	}
	fmt.Printf("  %-9s %d active evidence, %d derived paths\n", "lineage", snapshot.LineageLive, snapshot.LineageSize)
	if snapshot.LineageWarn {
		fmt.Printf("             Warning: derived lineage crossed the operability budget.\n")
		fmt.Printf("             Fix: finish the current task, then start a fresh agent session if lineage keeps growing.\n")
	}
}

func printDoctorOperability(projectRoot string, state *session.State, ledgerCount int, runtimeInspection *session.RuntimeContainmentInspection) {
	snapshot := inspectOperability(projectRoot, state, ledgerCount)
	if snapshot.Telemetry == nil || !snapshot.Telemetry.EndpointConfigured {
		fmt.Println("  [ok] telemetry: disabled")
	} else if snapshot.Telemetry.DroppedCount > 0 {
		fmt.Printf("  WARNING: telemetry dropped %d event(s) (queue %d x %d)\n",
			snapshot.Telemetry.DroppedCount,
			snapshot.Telemetry.QueueSize,
			snapshot.Telemetry.WorkerCount,
		)
		fmt.Println("           Fix: verify collector reachability or unset SIR_OTLP_ENDPOINT to disable export.")
	} else {
		fmt.Printf("  [ok] telemetry: queue %d x %d, dropped 0 events\n",
			snapshot.Telemetry.QueueSize,
			snapshot.Telemetry.WorkerCount,
		)
	}

	fmt.Printf("  [ok] lineage: %d active evidence item(s), %d derived path(s)\n", snapshot.LineageLive, snapshot.LineageSize)
	if snapshot.LineageWarn {
		fmt.Printf("  WARNING: derived lineage tracks %d paths; investigate if the session should be reset before it grows further.\n", snapshot.LineageSize)
		fmt.Println("           Fix: finish the current task, then start a fresh agent session if the count keeps rising.")
	}

	if runtimeInspection != nil {
		switch runtimeInspection.Health {
		case session.RuntimeContainmentStale:
			fmt.Printf("  WARNING: runtime containment is stale (%s)\n", runtimeInspection.Reason)
			if warning := runtimeContainmentWarning(runtimeInspection); warning != "" {
				fmt.Printf("           Warning: %s.\n", strings.TrimSuffix(warning, "."))
			}
			if impact := runtimeContainmentImpact(runtimeInspection); impact != "" {
				fmt.Printf("           Impact: %s.\n", strings.TrimSuffix(impact, "."))
			}
			fmt.Println("           Fix: rerun `sir run <agent>` or let `sir doctor` prune stale runtime state.")
		case session.RuntimeContainmentDegraded:
			fmt.Printf("  WARNING: runtime containment is degraded (%s)\n", runtimeInspection.Reason)
			if warning := runtimeContainmentWarning(runtimeInspection); warning != "" {
				fmt.Printf("           Warning: %s.\n", strings.TrimSuffix(warning, "."))
			}
			if impact := runtimeContainmentImpact(runtimeInspection); impact != "" {
				fmt.Printf("           Impact: %s.\n", strings.TrimSuffix(impact, "."))
			}
			for _, fix := range runtimeContainmentFixes(runtimeInspection) {
				fmt.Printf("           Fix: %s.\n", strings.TrimSuffix(fix, "."))
			}
		}
	}

	if snapshot.LedgerWarn {
		fmt.Printf("  WARNING: ledger.jsonl is %s across %d entries; explain/status latency may degrade as it grows.\n",
			formatBytes(snapshot.LedgerSize),
			ledgerCount,
		)
		fmt.Println("           Fix: archive the project state if you no longer need deep local history.")
	}
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(n)/1024.0)
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024.0*1024.0))
}
