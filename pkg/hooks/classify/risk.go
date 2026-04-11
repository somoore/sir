package classify

import "github.com/somoore/sir/pkg/policy"

// VerbRisk returns the relative risk of a classified shell verb.
func VerbRisk(verb policy.Verb) int {
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
