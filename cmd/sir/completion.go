package main

import (
	"fmt"
	"strings"
)

// topLevelCommands is the user-facing command list for shell completion.
var topLevelCommands = []string{
	"setup", "install", "uninstall", "update", "status", "doctor", "verify", "version",
	"capabilities", "posture", "demo",
	"why", "explain", "approvals", "approve", "unlock", "secret",
	"allow-host", "allow-remote", "trust",
	"policy", "protect-path", "unprotect-path", "mcp",
	"friction", "audit", "log", "replay", "trace",
	"relay", "run", "help",
}

// cmdCompletion prints a shell completion script for bash, zsh, or fish.
func cmdCompletion(args []string) {
	if len(args) != 1 {
		fatal("usage: sir completion bash|zsh|fish")
	}
	cmds := strings.Join(topLevelCommands, " ")
	switch args[0] {
	case "bash":
		fmt.Printf(`# sir bash completion — add to ~/.bashrc:  source <(sir completion bash)
_sir() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "%s" -- "$cur") )
  fi
}
complete -F _sir sir
`, cmds)
	case "zsh":
		fmt.Printf(`#compdef sir
# sir zsh completion — add to ~/.zshrc:  source <(sir completion zsh)
_sir() {
  local -a cmds
  cmds=(%s)
  _describe 'sir command' cmds
}
compdef _sir sir
`, cmds)
	case "fish":
		fmt.Printf("# sir fish completion — save to ~/.config/fish/completions/sir.fish\ncomplete -c sir -f -n '__fish_use_subcommand' -a '%s'\n", cmds)
	default:
		fatal("unsupported shell %q (supported: bash, zsh, fish)", args[0])
	}
}
