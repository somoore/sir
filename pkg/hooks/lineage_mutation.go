package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// propagateBashLineageMutation copies persistent lineage from a known derived
// source path onto a new destination path for simple archive, rename, copy,
// and link laundering commands.
//
// The goal is not to build a general shell parser. We only cover the small set
// of direct file transforms that otherwise let a derived artifact be renamed or
// linked under a fresh name and later lose its lineage surface.
func propagateBashLineageMutation(projectRoot string, state *session.State, payload *PostHookPayload) {
	if state == nil || payload == nil || payload.ToolName != "Bash" {
		return
	}
	command, _ := payload.ToolInput["command"].(string)
	command = strings.TrimSpace(command)
	if command == "" {
		return
	}

	normalized := normalizeCommand(command)
	if normalized == "" {
		normalized = command
	}
	if inner, ok := extractShellWrapperInner(normalized); ok {
		normalized = inner
	}

	for _, segment := range splitCompoundCommand(normalized) {
		segment = normalizeCommand(strings.TrimSpace(segment))
		if segment == "" {
			continue
		}
		sources, dest, ok := parseBashLineageMutation(segment)
		if !ok {
			continue
		}
		for _, source := range sources {
			sourcePath := ResolveTarget(projectRoot, source)
			destPath := resolveLineageMutationDestination(projectRoot, sourcePath, dest)
			mirrorDerivedLineage(state, sourcePath, destPath)
		}
	}
}

func parseBashLineageMutation(cmd string) (sources []string, dest string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 3 {
		return nil, "", false
	}

	switch filepath.Base(parts[0]) {
	case "cp", "mv", "ln":
	default:
		return nil, "", false
	}

	operands := make([]string, 0, len(parts)-1)
	skipNext := false
	for _, part := range parts[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if part == "" || strings.HasPrefix(part, "-") {
			continue
		}
		if isShellRedirectionToken(part) {
			if shellRedirectionConsumesFollowingToken(part) {
				skipNext = true
			}
			continue
		}
		operand := strings.Trim(part, "\"'`")
		if operand == "" {
			continue
		}
		operands = append(operands, operand)
	}
	if len(operands) < 2 {
		return nil, "", false
	}
	return operands[:len(operands)-1], operands[len(operands)-1], true
}

func resolveLineageMutationDestination(projectRoot, sourcePath, dest string) string {
	destPath := ResolveTarget(projectRoot, dest)
	if destPath == "" {
		return ""
	}
	if !isLineageMutationDirectoryDestination(dest, destPath) {
		return destPath
	}
	base := filepath.Base(sourcePath)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return destPath
	}
	return ResolveTarget(projectRoot, filepath.Join(dest, base))
}

func isLineageMutationDirectoryDestination(dest, resolvedDest string) bool {
	if strings.HasSuffix(dest, string(os.PathSeparator)) {
		return true
	}
	if info, err := os.Stat(resolvedDest); err == nil && info.IsDir() {
		return true
	}
	return false
}

func mirrorDerivedLineage(state *session.State, sourcePath, destPath string) {
	if sourcePath == "" || destPath == "" || sourcePath == destPath {
		return
	}
	if state.DerivedFileLineage == nil {
		state.DerivedFileLineage = make(map[string]session.DerivedPathRecord)
	}
	sourceRecord, ok := state.DerivedFileLineage[sourcePath]
	if !ok || len(sourceRecord.Labels) == 0 {
		return
	}
	if destRecord, ok := state.DerivedFileLineage[destPath]; ok {
		sourceRecord.EvidenceIDs = appendMissingStrings(destRecord.EvidenceIDs, sourceRecord.EvidenceIDs)
		sourceRecord.Labels = mergeHookLineageLabels(destRecord.Labels, sourceRecord.Labels)
	}
	sourceRecord.UpdatedAt = time.Now()
	state.DerivedFileLineage[destPath] = sourceRecord
}

func appendMissingStrings(dst, src []string) []string {
	out := append([]string(nil), dst...)
	for _, value := range src {
		if !containsString(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mergeHookLineageLabels(dst, src []session.LineageLabel) []session.LineageLabel {
	out := make([]session.LineageLabel, 0, len(dst)+len(src))
	out = append(out, dst...)
	out = append(out, src...)
	seen := make(map[session.LineageLabel]struct{}, len(out))
	merged := make([]session.LineageLabel, 0, len(out))
	for _, label := range out {
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		merged = append(merged, label)
	}
	return merged
}

func isShellRedirectionToken(token string) bool {
	if token == "" {
		return false
	}
	if strings.HasPrefix(token, "2>&1") || strings.HasPrefix(token, "&>") {
		return true
	}
	for _, prefix := range []string{
		">>", "<<", "1>>", "2>>", "1>", "2>", ">", "<",
	} {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

func shellRedirectionConsumesFollowingToken(token string) bool {
	switch token {
	case ">", ">>", "<", "<<", "1>", "1>>", "2>", "2>>", "&>":
		return true
	default:
		return false
	}
}
