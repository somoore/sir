package runtime

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

// Options are the parsed `sir run` arguments.
type Options struct {
	Agent        agent.Agent
	AllowedHosts []string
	Passthrough  []string
}

// ParseOptions parses `sir run` arguments into an Options value.
func ParseOptions(args []string) (Options, error) {
	if len(args) == 0 {
		return Options{}, fmt.Errorf("usage: sir run <agent> [--allow-host host]... [-- <agent args...>]")
	}
	ag := agent.ForID(agent.AgentID(args[0]))
	if ag == nil {
		return Options{}, fmt.Errorf("unknown agent %q (supported: %s)", args[0], supportedAgentIDs())
	}

	opts := Options{Agent: ag}
	for i := 1; i < len(args); {
		if args[i] == "--" {
			opts.Passthrough = append(opts.Passthrough, args[i+1:]...)
			break
		}
		if args[i] == "--allow-host" {
			if i+1 >= len(args) {
				return Options{}, fmt.Errorf("sir run: --allow-host requires a value")
			}
			opts.AllowedHosts = append(opts.AllowedHosts, args[i+1])
			i += 2
			continue
		}
		opts.Passthrough = append(opts.Passthrough, args[i:]...)
		break
	}
	return opts, nil
}

// ResolveBinary finds the agent binary to launch under containment.
func ResolveBinary(ag agent.Agent) (string, error) {
	if ag == nil {
		return "", fmt.Errorf("runtime launch requires a non-nil agent")
	}
	candidates := BinaryCandidates(ag)
	for _, bin := range candidates {
		if path, err := exec.LookPath(bin); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s binary not found on PATH (looked for: %s)", ag.Name(), strings.Join(candidates, ", "))
}

// BinaryCandidates returns the possible binary names for an agent.
func BinaryCandidates(ag agent.Agent) []string {
	if ag == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	if spec := ag.GetSpec(); spec != nil {
		for _, bin := range spec.BinaryNames {
			if bin == "" {
				continue
			}
			if _, ok := seen[bin]; ok {
				continue
			}
			seen[bin] = struct{}{}
			out = append(out, bin)
		}
	}
	if fallback := string(ag.ID()); fallback != "" {
		if _, ok := seen[fallback]; !ok {
			out = append(out, fallback)
		}
	}
	return out
}

func supportedAgentIDs() string {
	ids := make([]string, 0, len(agent.All()))
	for _, ag := range agent.All() {
		ids = append(ids, string(ag.ID()))
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}
