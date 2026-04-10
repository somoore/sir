package main

import (
	"fmt"

	"github.com/somoore/sir/pkg/agent"
)

func printDoctorAgentChecks(statuses []agentStatus) (bool, bool) {
	sawAnyInstalled := false
	schemaFixed := false

	for _, status := range statuses {
		if !status.Installed {
			continue
		}
		sawAnyInstalled = true
		if status.ReadErr != nil {
			fmt.Printf("  WARNING: %s: could not read hook configuration: %v\n", status.Agent.Name(), status.ReadErr)
			continue
		}

		supportPreview := agent.SupportManifestForAgent(status.Agent).StatusSuffix()
		if len(status.Missing) > 0 {
			fmt.Printf("  WARNING: %s: %d/%d hook events registered. Missing:\n", status.Agent.Name(), status.Found, status.Total)
			for _, event := range status.Missing {
				fmt.Printf("    - %s\n", event)
			}
			fmt.Println("  Run 'sir install' to register all hooks.")
		} else {
			fmt.Printf("  [ok] %s: all %d hook events registered%s\n", status.Agent.Name(), status.Total, supportPreview)
		}

		if spec := status.Agent.GetSpec(); spec != nil && spec.MinVersion != "" {
			for _, bin := range spec.BinaryNames {
				if installed := agent.DetectInstalledVersion(bin); installed != "" {
					if agent.SemverLessThan(installed, spec.MinVersion) {
						fmt.Printf("  warn  %s %s detected; sir requires %s+\n", status.Agent.Name(), installed, spec.MinVersion)
					}
					break
				}
			}
		}

		if len(status.SchemaInval) > 0 {
			fmt.Printf("  [!!] CRITICAL: %s: %d hook event(s) use invalid schema:\n", status.Agent.Name(), len(status.SchemaInval))
			for _, event := range status.SchemaInval {
				fmt.Printf("    - %s (missing 'hooks' array wrapper)\n", event)
			}
			fmt.Println("  Run 'sir install' to fix. This is the #1 cause of sir being completely inert.")
			schemaFixed = true
		} else {
			fmt.Printf("  [ok] %s: hook schema valid\n", status.Agent.Name())
		}

		if spec := status.Agent.GetSpec(); spec != nil && spec.RequiredFeatureFlag != "" {
			configPath, featureStatus, supported := featureFlagStatusForAgent(status.Agent)
			if !supported {
				fmt.Printf("  [!!] WARNING: %s: feature flag validation for %s is not implemented yet\n", status.Agent.Name(), spec.RequiredFeatureFlag)
				continue
			}
			switch featureStatus {
			case codexFlagAlreadyEnabled:
				fmt.Printf("  [ok] %s: %s feature flag enabled in %s\n", status.Agent.Name(), spec.RequiredFeatureFlag, configPath)
			case codexFlagMissingFile:
				fmt.Printf("  [!!] WARNING: %s: %s does not exist yet\n", status.Agent.Name(), configPath)
				fmt.Printf("        Run '%s' (or create the file with [features]\\n%s = true).\n", spec.FeatureFlagEnableCommand, spec.RequiredFeatureFlag)
			case codexFlagNeedsEnable:
				fmt.Printf("  [!!] WARNING: %s: %s=true is NOT set under [features] in %s\n", status.Agent.Name(), spec.RequiredFeatureFlag, configPath)
				fmt.Printf("        Hooks are written but %s will NOT fire them until the feature flag is enabled.\n", status.Agent.Name())
				fmt.Printf("        Fix: %s\n", spec.FeatureFlagEnableCommand)
			case codexFlagUnreadable:
				fmt.Printf("  [!!] WARNING: %s: could not read %s - unable to verify %s flag\n", status.Agent.Name(), configPath, spec.RequiredFeatureFlag)
			}
		}
	}

	if !sawAnyInstalled {
		fmt.Println("  WARNING: no supported agent detected. Run 'sir install' after installing Claude Code, Codex, or Gemini CLI.")
	}
	printDoctorSupportWarnings(statuses)
	return sawAnyInstalled, schemaFixed
}
