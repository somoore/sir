package hooks

import hookclassify "github.com/somoore/sir/pkg/hooks/classify"

// isSirSelfCommand returns true when the command modifies sir itself.
// Prevents an agent from silently running "sir uninstall" to remove hook protection.
// "sir install", "sir uninstall", "sir clear session", and "sir reset" are gated.
// "sir status", "sir doctor", "sir log", "sir explain", "sir version" are informational and allowed.
func isSirSelfCommand(cmd string) bool {
	return hookclassify.IsSirSelfCommand(cmd)
}

// containsSirSelfCommand splits a compound command on shell operators (|, &&, ||, ;)
// and returns true if ANY segment contains a sir self-modification command.
func containsSirSelfCommand(cmd string) bool {
	return hookclassify.ContainsSirSelfCommand(cmd)
}

// targetsSirStateFiles returns true when the command appears to target ~/.sir/ state files
// using tools like sed, awk, perl, python, chmod, chown, mv, cp, tee, dd.
func targetsSirStateFiles(cmd string) bool {
	return hookclassify.TargetsSirStateFiles(cmd)
}
