package main

// cmdTrust is the unified durable-grant verb. It nests the previously scattered
// grant commands under one noun-space with a consistent --remove:
//
//	sir trust host <h> [--ttl D] [--remove]   (== allow-host)
//	sir trust remote <r> [--remove]           (== allow-remote)
//	sir trust mcp <s> [--remove]              (== trust, credential-scan exempt)
//	sir trust path <p> [--posture] [--remove] (== protect-path / unprotect-path)
//
// The legacy top-level verbs (allow-host, allow-remote, trust <server>,
// protect-path) still work as aliases, so nothing breaks. A bare
// `sir trust <server>` keeps its historical meaning (MCP credential trust).
func cmdTrust(projectRoot string, args []string) {
	if len(args) == 0 {
		fatal("usage: sir trust host|remote|mcp|path <name> [--ttl D] [--remove] [--yes]")
	}
	switch args[0] {
	case "host":
		cmdAllowHostArgs(projectRoot, args[1:])
	case "remote":
		cmdAllowRemoteArgs(projectRoot, args[1:])
	case "mcp":
		cmdTrustMCPArgs(projectRoot, args[1:])
	case "path":
		cmdTrustPath(projectRoot, args[1:])
	default:
		// Legacy form: `sir trust <server>` == MCP credential trust.
		cmdTrustMCPArgs(projectRoot, args)
	}
}

// cmdTrustPath routes `sir trust path <p>` to protect/unprotect based on --remove.
func cmdTrustPath(projectRoot string, args []string) {
	if len(args) == 0 {
		fatal("usage: sir trust path <path> [--posture] [--remove]")
	}
	remove := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--remove" || a == "--revoke" {
			remove = true
			continue
		}
		rest = append(rest, a)
	}
	if remove {
		cmdUnprotectPath(projectRoot, rest)
		return
	}
	cmdProtectPath(projectRoot, rest)
}
