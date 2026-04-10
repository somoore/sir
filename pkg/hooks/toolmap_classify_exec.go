package hooks

import hookclassify "github.com/somoore/sir/pkg/hooks/classify"

func isGitPush(cmd string) bool {
	return hookclassify.IsGitPush(cmd)
}

func isGitCommit(cmd string) bool {
	return hookclassify.IsGitCommit(cmd)
}

func gitSubcommandIs(cmd, subcmd string) bool {
	return hookclassify.GitSubcommandIs(cmd, subcmd)
}

func isEnvCommand(cmd string) bool {
	return hookclassify.IsEnvCommand(cmd)
}

func isPersistenceCommand(cmd string) bool {
	return hookclassify.IsPersistenceCommand(cmd)
}

func isSudoCommand(cmd string) bool {
	return hookclassify.IsSudoCommand(cmd)
}
