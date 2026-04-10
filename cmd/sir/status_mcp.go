package main

import (
	"fmt"
	"path/filepath"
)

func printMCPStatus(report mcpInventoryReport) {
	if len(report.Servers) == 0 && len(report.Errors) == 0 {
		return
	}
	fmt.Println("  MCP:")
	for _, server := range report.Servers {
		assessment := server.RuntimeAssessment()
		mark := "ok"
		if assessment.NeedsAttention {
			mark = "!!"
		}
		fmt.Printf("    %-2s %-16s %s  %s\n", mark, server.Name, server.SourceLabel, assessment.Summary)
	}
	for _, invErr := range report.Errors {
		fmt.Printf("    !! %-16s %s  parse error: %v\n", filepath.Base(invErr.Path), invErr.Path, invErr.Err)
	}
	fmt.Println()
}

func printDoctorMCPStatus(report mcpInventoryReport) {
	for _, server := range report.Servers {
		assessment := server.RuntimeAssessment()
		if assessment.NeedsAttention {
			fmt.Printf("  WARNING: MCP %s in %s is %s\n", server.Name, server.SourceLabel, assessment.Summary)
			fmt.Printf("           Fix: %s\n", assessment.Warning)
			continue
		}
		fmt.Printf("  [ok] MCP %s in %s: %s\n", server.Name, server.SourceLabel, assessment.Summary)
	}
	for _, invErr := range report.Errors {
		fmt.Printf("  WARNING: could not parse %s: %v\n", invErr.Path, invErr.Err)
	}
}
