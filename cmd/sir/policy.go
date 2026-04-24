package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func cmdPolicy(projectRoot string, args []string) {
	if len(args) == 0 {
		fatal("usage: sir policy [show|diff|init|protect-path|unprotect-path] ...")
	}
	subcmd := args[0]
	args = args[1:]
	switch subcmd {
	case "show":
		cmdPolicyShow(projectRoot, args)
	case "diff":
		cmdPolicyDiff(projectRoot, args)
	case "init":
		cmdPolicyInit(projectRoot, args)
	case "protect-path":
		cmdProtectPath(projectRoot, args)
	case "unprotect-path":
		cmdUnprotectPath(projectRoot, args)
	default:
		fatal("usage: sir policy [show|diff|init|protect-path|unprotect-path] ...")
	}
}

func cmdPolicyShow(projectRoot string, args []string) {
	asJSON := len(args) > 0 && args[0] == "--json"
	l, err := loadProjectLease(projectRoot)
	if err != nil {
		if os.IsNotExist(err) {
			l = lease.DefaultLease()
		} else {
			fatal("load lease: %v", err)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(l); err != nil {
			fatal("encode policy: %v", err)
		}
		return
	}
	fmt.Println("sir policy show")
	fmt.Println()
	fmt.Printf("  mode:            %s\n", l.Mode)
	fmt.Printf("  delegation:      %v\n", l.AllowDelegation)
	fmt.Printf("  approved hosts:  %s\n", strings.Join(l.ActiveApprovedHosts(), ", "))
	if len(l.ApprovedHostExpires) > 0 {
		fmt.Println("  host TTLs:")
		for _, host := range sortedMapKeys(l.ApprovedHostExpires) {
			fmt.Printf("    - %s expires %s\n", host, l.ApprovedHostExpires[host].Format("2006-01-02 15:04:05 MST"))
		}
	}
	fmt.Printf("  approved remotes:%s\n", prefixedList(l.ApprovedRemotes))
	fmt.Printf("  approved MCP:    %s\n", strings.Join(l.ApprovedMCPServers, ", "))
	if len(l.MCPCapabilityScopes) > 0 {
		fmt.Println("  MCP scopes:")
		for _, scope := range l.MCPCapabilityScopes {
			fmt.Printf("    - %s shell=%v network=%v write=%v tools=%v roots=%v\n",
				scope.Server, scope.AllowShell, scope.AllowNetwork, scope.AllowWrite, scope.Tools, scope.Roots)
		}
	}
	fmt.Printf("  sensitive paths:%s\n", prefixedList(l.SensitivePaths))
	fmt.Printf("  posture files:  %s\n", strings.Join(l.PostureFiles, ", "))
	fmt.Printf("  ask verbs:      %s\n", joinVerbs(l.AskVerbs))
	fmt.Printf("  forbidden verbs:%s\n", prefixedListVerbs(l.ForbiddenVerbs))
	fmt.Printf("  lease path:     %s\n", filepath.Join(session.StateDir(projectRoot), "lease.json"))
}

func cmdPolicyDiff(projectRoot string, args []string) {
	profile := "default"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			if i+1 >= len(args) {
				fatal("--profile requires default or strict")
			}
			profile = args[i+1]
			i++
		case "--strict":
			profile = "strict"
		}
	}
	current, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}
	target, err := leaseForProfile(profile)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("sir policy diff --profile %s\n\n", profile)
	printLeaseDiff("approved_hosts", current.ApprovedHosts, target.ApprovedHosts)
	printLeaseDiff("approved_remotes", current.ApprovedRemotes, target.ApprovedRemotes)
	printLeaseDiff("approved_mcp_servers", current.ApprovedMCPServers, target.ApprovedMCPServers)
	printLeaseDiff("sensitive_paths", current.SensitivePaths, target.SensitivePaths)
	printLeaseDiff("posture_files", current.PostureFiles, target.PostureFiles)
	printLeaseDiff("allowed_verbs", verbStrings(current.AllowedVerbs), verbStrings(target.AllowedVerbs))
	printLeaseDiff("ask_verbs", verbStrings(current.AskVerbs), verbStrings(target.AskVerbs))
	printLeaseDiff("forbidden_verbs", verbStrings(current.ForbiddenVerbs), verbStrings(target.ForbiddenVerbs))
	if current.AllowDelegation != target.AllowDelegation {
		fmt.Printf("  allow_delegation: current=%v target=%v\n", current.AllowDelegation, target.AllowDelegation)
	}
	if reflect.DeepEqual(current, target) {
		fmt.Println("  no differences")
	}
}

func cmdPolicyInit(projectRoot string, args []string) {
	if err := ensureManagedCommandAllowed("policy init"); err != nil {
		fatal("%v", err)
	}
	profile := "default"
	yes := false
	for _, arg := range args {
		switch arg {
		case "--strict":
			profile = "strict"
		case "--default", "--standard":
			profile = "default"
		case "--yes", "-y":
			yes = true
		default:
			fatal("usage: sir policy init [--strict|--default] [--yes]")
		}
	}
	l, err := leaseForProfile(profile)
	if err != nil {
		fatal("%v", err)
	}
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	if !yes {
		fmt.Printf("Write %s policy to %s? [y/N] ", profile, leasePath)
		var confirm string
		fmt.Scanln(&confirm)
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Cancelled. No changes made.")
			return
		}
	}
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(current *lease.Lease) error {
		*current = *l
		return nil
	}); err != nil {
		fatal("save lease and refresh session baseline: %v", err)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "policy_profile",
		Decision: "allow",
		Reason:   fmt.Sprintf("initialized %s policy profile", profile),
	})
	fmt.Printf("Initialized %s policy profile.\n", profile)
}

func cmdProtectPath(projectRoot string, args []string) {
	cmdPathProtection(projectRoot, args, true)
}

func cmdUnprotectPath(projectRoot string, args []string) {
	cmdPathProtection(projectRoot, args, false)
}

func cmdPathProtection(projectRoot string, args []string, protect bool) {
	if err := ensureManagedCommandAllowed("policy path"); err != nil {
		fatal("%v", err)
	}
	if len(args) == 0 {
		fatal("usage: sir protect-path <path> [--sensitive|--posture]")
	}
	path := args[0]
	kind := "sensitive"
	for _, arg := range args[1:] {
		switch arg {
		case "--sensitive":
			kind = "sensitive"
		case "--posture":
			kind = "posture"
		default:
			fatal("unknown flag: %s", arg)
		}
	}
	action := "protected"
	if !protect {
		action = "unprotected"
	}
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		switch kind {
		case "sensitive":
			if protect {
				l.SensitivePaths = appendUniqueString(l.SensitivePaths, path)
			} else {
				l.SensitivePaths = removeString(l.SensitivePaths, path)
			}
		case "posture":
			if protect {
				l.PostureFiles = appendUniqueString(l.PostureFiles, path)
			} else {
				l.PostureFiles = removeString(l.PostureFiles, path)
			}
		}
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   path,
		Decision: "allow",
		Reason:   fmt.Sprintf("%s %s path", action, kind),
	})
	fmt.Printf("%s %q as %s.\n", capitalize(action), path, kind)
}

func leaseForProfile(profile string) (*lease.Lease, error) {
	switch profile {
	case "default", "standard":
		return lease.DefaultLease(), nil
	case "strict":
		l := lease.DefaultLease()
		l.Mode = "strict"
		l.ApprovedRemotes = nil
		l.ApprovedMCPServers = nil
		l.AllowDelegation = false
		l.ApprovedHosts = []string{"localhost", "127.0.0.1", "::1"}
		l.AllowedVerbs = removeVerb(l.AllowedVerbs, policy.VerbPushOrigin)
		l.AllowedVerbs = removeVerb(l.AllowedVerbs, policy.VerbDelegate)
		l.AskVerbs = appendUniqueVerb(l.AskVerbs, policy.VerbPushOrigin)
		l.AskVerbs = appendUniqueVerb(l.AskVerbs, policy.VerbDelegate)
		return l, nil
	default:
		return nil, fmt.Errorf("unknown profile %q (valid: default, strict)", profile)
	}
}

func printLeaseDiff(name string, current, target []string) {
	added, removed := stringDiff(current, target)
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	fmt.Printf("  %s:\n", name)
	if len(added) > 0 {
		fmt.Printf("    add:    %s\n", strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		fmt.Printf("    remove: %s\n", strings.Join(removed, ", "))
	}
}

func stringDiff(current, target []string) (added, removed []string) {
	cur := make(map[string]struct{}, len(current))
	want := make(map[string]struct{}, len(target))
	for _, v := range current {
		cur[v] = struct{}{}
	}
	for _, v := range target {
		want[v] = struct{}{}
		if _, ok := cur[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range current {
		if _, ok := want[v]; !ok {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func appendUniqueString(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

func removeString(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func appendUniqueVerb(xs []policy.Verb, x policy.Verb) []policy.Verb {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

func removeVerb(xs []policy.Verb, x policy.Verb) []policy.Verb {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func verbStrings(xs []policy.Verb) []string {
	out := make([]string, 0, len(xs))
	for _, v := range xs {
		out = append(out, string(v))
	}
	return out
}

func joinVerbs(xs []policy.Verb) string {
	return strings.Join(verbStrings(xs), ", ")
}

func prefixedList(xs []string) string {
	if len(xs) == 0 {
		return " (none)"
	}
	return " " + strings.Join(xs, ", ")
}

func prefixedListVerbs(xs []policy.Verb) string {
	if len(xs) == 0 {
		return " (none)"
	}
	return " " + joinVerbs(xs)
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
