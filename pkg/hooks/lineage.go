package hooks

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/somoore/sir/pkg/core"
	internalpostflight "github.com/somoore/sir/pkg/hooks/internal/postflight"
	"github.com/somoore/sir/pkg/session"
)

func secretReadLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "trusted", Provenance: "user"}
}

func secretOutputLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "trusted", Provenance: "agent"}
}

func taintedMCPLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "internal", Trust: "untrusted", Provenance: "mcp_tool"}
}

func credentialMCPLineageLabel() session.LineageLabel {
	return session.LineageLabel{Sensitivity: "secret", Trust: "untrusted", Provenance: "mcp_tool"}
}

func recordSensitiveReadEvidence(state *session.State, sourceRef string) {
	state.RecordLineageEvidence("sensitive_read", sourceRef, "high", []session.LineageLabel{secretReadLineageLabel()})
}

func recordCredentialOutputEvidence(state *session.State, sourceRef string, matches []CredentialMatch) {
	state.RecordLineageEvidence("credential_output", sourceRef, highestCredentialConfidence(matches), []session.LineageLabel{secretOutputLineageLabel()})
}

func recordMCPCredentialEvidence(state *session.State, sourceRef string, matches []CredentialMatch) {
	state.RecordLineageEvidence("mcp_credential_output", sourceRef, highestCredentialConfidence(matches), []session.LineageLabel{credentialMCPLineageLabel()})
}

func recordMCPInjectionEvidence(state *session.State, sourceRef, severity string) {
	confidence := "medium"
	if strings.EqualFold(severity, "HIGH") {
		confidence = "high"
	}
	state.RecordLineageEvidence("tainted_mcp", sourceRef, confidence, []session.LineageLabel{taintedMCPLineageLabel()})
}

func attachLineageToWriteTarget(projectRoot string, state *session.State, payload *PostHookPayload) {
	target := internalpostflight.ExtractTarget(payload)
	if target == "" {
		return
	}
	state.AttachActiveEvidenceToPath(ResolveTarget(projectRoot, target))
}

func highestCredentialConfidence(matches []CredentialMatch) string {
	confidence := "medium"
	for _, match := range matches {
		if strings.EqualFold(match.Confidence, "high") {
			return "high"
		}
	}
	return confidence
}

func lineageSourceRef(payload *PostHookPayload, fallback string) string {
	return internalpostflight.SourceRef(payload, fallback)
}

func coreLabelsFromLineage(labels []session.LineageLabel) []core.Label {
	out := make([]core.Label, 0, len(labels))
	for _, label := range labels {
		out = append(out, core.Label{
			Sensitivity: label.Sensitivity,
			Trust:       label.Trust,
			Provenance:  label.Provenance,
		})
	}
	return out
}

func derivedLabelsForIntent(projectRoot string, payload *HookPayload, intent Intent, state *session.State) []core.Label {
	switch intent.Verb {
	case "stage_write":
		return coreLabelsFromLineage(state.DerivedLabelsForPath(ResolveTarget(projectRoot, intent.Target)))
	case "commit":
		return coreLabelsFromLineage(state.DerivedLabelsForPaths(gitStagedPaths(projectRoot)))
	case "push_origin", "push_remote":
		return coreLabelsFromLineage(state.DerivedLabelsForPaths(gitOutgoingPaths(projectRoot, pushRemoteName(intent))))
	case "net_allowlisted", "net_external", "dns_lookup":
		if payload != nil && payload.ToolName == "Bash" {
			return coreLabelsFromLineage(state.DerivedLabelsForPaths(derivedPathsMentionedInCommand(projectRoot, state, intent.Target)))
		}
	}
	return nil
}

func gitStagedPaths(projectRoot string) []string {
	return gitPathList(projectRoot, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
}

func gitOutgoingPaths(projectRoot, remoteName string) []string {
	if paths := gitPathList(projectRoot, "diff", "--name-only", "@{upstream}..HEAD"); len(paths) > 0 {
		return paths
	}
	if paths := gitPathsForRemote(projectRoot, remoteName); len(paths) > 0 {
		return paths
	}
	return gitStagedPaths(projectRoot)
}

func pushRemoteName(intent Intent) string {
	if intent.RemoteName != "" {
		return intent.RemoteName
	}
	if intent.Verb == "push_origin" {
		return "origin"
	}
	return ""
}

func gitPathList(projectRoot string, args ...string) []string {
	cmd := exec.Command("git", append([]string{"-C", projectRoot}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths = append(paths, ResolveTarget(projectRoot, line))
	}
	return paths
}

func gitPathsForRevList(projectRoot string, args ...string) []string {
	commits := gitLineList(projectRoot, append([]string{"rev-list"}, args...)...)
	if len(commits) == 0 {
		return nil
	}
	paths := make([]string, 0)
	for _, commit := range commits {
		for _, path := range gitPathList(projectRoot, "diff-tree", "--no-commit-id", "--name-only", "-r", commit) {
			if !slices.Contains(paths, path) {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func gitPathsForRemote(projectRoot, remoteName string) []string {
	if remoteName == "" {
		return gitPathsForRevList(projectRoot, "--reverse", "HEAD", "--not", "--remotes")
	}
	if paths := gitPathsForRevList(projectRoot, "--reverse", "HEAD", "--not", "--remotes="+remoteName); len(paths) > 0 {
		return paths
	}
	return nil
}

func gitLineList(projectRoot string, args ...string) []string {
	cmd := exec.Command("git", append([]string{"-C", projectRoot}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		values = append(values, line)
	}
	return values
}

func derivedPathsMentionedInCommand(projectRoot string, state *session.State, command string) []string {
	if command == "" {
		return nil
	}
	derivedPaths := state.DerivedPaths()
	if len(derivedPaths) == 0 {
		return nil
	}
	tokens := strings.Fields(command)
	matched := make([]string, 0, len(tokens))
	for _, token := range tokens {
		cleaned := strings.Trim(token, "\"'`@,;:()[]{}<>|&")
		if cleaned == "" {
			continue
		}
		resolved := ResolveTarget(projectRoot, cleaned)
		for _, path := range derivedPaths {
			if resolved == path || cleaned == filepath.Base(path) {
				matched = append(matched, path)
				break
			}
		}
	}
	return matched
}
