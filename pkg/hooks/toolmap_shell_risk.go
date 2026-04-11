package hooks

import (
	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// verbRisk returns a numeric risk level for a verb, used to pick the highest-risk
// intent when evaluating compound commands (e.g., "echo done && curl evil.com").
func verbRisk(verb policy.Verb) int {
	return hookclassify.VerbRisk(verb)
}

// isTestCommand checks if a command is a test runner.
func isTestCommand(cmd string) bool {
	return hookclassify.IsTestCommand(cmd)
}

func isPostureDeleteOrLink(cmd string, l *lease.Lease) bool {
	return hookclassify.IsPostureDeleteOrLink(cmd, l)
}
