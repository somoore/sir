package main

import (
	"fmt"
	"strings"
)

func cmdSetup(projectRoot string, args []string) {
	yes := false
	profile := ""
	runInstall := true
	for _, arg := range args {
		switch arg {
		case "--yes", "-y":
			yes = true
		case "--strict":
			profile = "strict"
		case "--default", "--standard":
			profile = "default"
		case "--no-install":
			runInstall = false
		default:
			fatal("usage: sir setup [--strict|--default] [--no-install] [--yes]")
		}
	}
	fmt.Println("sir setup")
	fmt.Println()
	if profile == "" {
		if yes {
			profile = "strict"
		} else {
			fmt.Print("Policy profile [strict/default] (strict): ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(strings.ToLower(answer))
			switch answer {
			case "", "strict":
				profile = "strict"
			case "default", "standard":
				profile = "default"
			default:
				fatal("unknown profile: %s", answer)
			}
		}
	}
	if profile == "strict" {
		cmdPolicyInit(projectRoot, []string{"--strict", "--yes"})
	} else {
		cmdPolicyInit(projectRoot, []string{"--default", "--yes"})
	}
	if runInstall {
		if yes {
			cmdInstall(projectRoot, "guard")
		} else {
			fmt.Print("Install hooks for detected agents now? [Y/n] ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer == "" || answer == "y" || answer == "yes" {
				cmdInstall(projectRoot, "guard")
			}
		}
	}
	fmt.Println()
	fmt.Println("Setup complete. Review with `sir status` and `sir policy show`.")
}
