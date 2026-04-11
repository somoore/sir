package hooks

import hookclassify "github.com/somoore/sir/pkg/hooks/classify"

// isNetworkCommand checks if a command starts with a network egress tool.
func isNetworkCommand(cmd string) bool {
	return hookclassify.IsNetworkCommand(cmd)
}

// extractNetworkDest extracts the URL/host from a curl/wget command.
func extractNetworkDest(cmd string) string {
	return hookclassify.ExtractNetworkDest(cmd)
}

// isDNSCommand detects DNS exfiltration prefixes (nslookup, dig, host, drill, whois).
func isDNSCommand(cmd string) bool {
	return hookclassify.IsDNSCommand(cmd)
}

func isPingCommand(cmd string) bool {
	return hookclassify.IsPingCommand(cmd)
}

// isInterpreterNetworkCommand returns true when a language interpreter is used in one-liner
// mode (-c or -e flag) and the command body contains network API patterns.
func isInterpreterNetworkCommand(cmd string) bool {
	return hookclassify.IsInterpreterNetworkCommand(cmd)
}
