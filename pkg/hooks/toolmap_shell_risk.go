package hooks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// verbRisk returns a numeric risk level for a verb, used to pick the highest-risk
// intent when evaluating compound commands (e.g., "echo done && curl evil.com").
func verbRisk(verb policy.Verb) int {
	switch verb {
	case policy.VerbSirSelf:
		return 100
	case policy.VerbNetExternal, policy.VerbDnsLookup, policy.VerbMcpCredentialLeak:
		return 90
	case policy.VerbPushRemote:
		return 85
	case policy.VerbNetAllowlisted, policy.VerbPushOrigin:
		return 70
	case policy.VerbRunEphemeral:
		return 65
	case policy.VerbEnvRead, policy.VerbPersistence, policy.VerbSudo, policy.VerbDeletePosture:
		return 60
	case policy.VerbStageWrite:
		return 50
	case policy.VerbNetLocal:
		return 40
	case policy.VerbExecuteDryRun:
		return 10
	case policy.VerbReadRef, policy.VerbListFiles, policy.VerbSearchCode, policy.VerbRunTests, policy.VerbCommit:
		return 5
	default:
		return 10
	}
}

// isTestCommand checks if a command is a test runner.
func isTestCommand(cmd string) bool {
	testPrefixes := []string{
		"go test", "npm test", "npm run test", "yarn test",
		"pytest", "python -m pytest", "python3 -m pytest",
		"cargo test", "make test", "bundle exec rspec",
		"jest", "vitest", "mocha",
	}
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range testPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func isPostureDeleteOrLink(cmd string, l *lease.Lease) bool {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 2 {
		return false
	}

	lower0 := strings.ToLower(parts[0])
	sirDir := globalSirDir()

	if lower0 == "rm" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if sirDir != "" {
				expanded := os.ExpandEnv(arg)
				if expanded == sirDir || strings.HasPrefix(expanded, sirDir+string(filepath.Separator)) {
					return true
				}
				if arg == "~/.sir" || strings.HasPrefix(arg, "~/.sir/") {
					return true
				}
			}
			if IsPostureFileResolved(arg, l) {
				return true
			}
		}
	}

	if lower0 == "ln" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if IsPostureFileResolved(arg, l) {
				return true
			}
		}
	}

	return false
}
