package hooks

import hookclassify "github.com/somoore/sir/pkg/hooks/classify"

// normalizeCommand strips absolute paths, env prefixes, and inline variable
// assignments so classifiers see bare command names regardless of invocation.
func normalizeCommand(cmd string) string {
	return hookclassify.NormalizeCommand(cmd)
}

// splitCompoundCommand splits a command string on shell compound operators.
// Quoted operators are preserved as part of the surrounding segment.
func splitCompoundCommand(cmd string) []string {
	return hookclassify.SplitCompoundCommand(cmd)
}

// stripSudoPrefix removes "sudo" and its flags to get the inner command.
func stripSudoPrefix(cmd string) string {
	return hookclassify.StripSudoPrefix(cmd)
}

// extractShellWrapperInner detects "bash -c '...'" / "sh -c '...'" patterns and
// returns the inner command for recursive classification.
func extractShellWrapperInner(cmd string) (string, bool) {
	return hookclassify.ExtractShellWrapperInner(cmd)
}

// flagTakesValue returns true for curl/wget flags that consume the next argument.
func flagTakesValue(flag string) bool {
	return hookclassify.FlagTakesValue(flag)
}
