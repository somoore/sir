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

	for _, segment := range splitBashScriptSegments(command) {
		segment = normalizeCommand(strings.TrimSpace(segment))
		if segment == "" {
			continue
		}
		if inner, ok := extractShellWrapperInner(segment); ok {
			segment = inner
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

func splitBashScriptSegments(cmd string) []string {
	var segments []string
	var current strings.Builder
	runes := []rune(cmd)
	i := 0
	inSingle := false
	inDouble := false

	flush := func() {
		segment := strings.TrimSpace(current.String())
		if segment != "" {
			segments = append(segments, segment)
		}
		current.Reset()
	}

	for i < len(runes) {
		ch := runes[i]

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			current.WriteRune(ch)
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			current.WriteRune(ch)
			i++
			continue
		}
		if inSingle || inDouble {
			current.WriteRune(ch)
			i++
			continue
		}

		switch ch {
		case '|':
			flush()
			if i+1 < len(runes) && runes[i+1] == '|' {
				i += 2
			} else {
				i++
			}
		case '&':
			flush()
			if i+1 < len(runes) && runes[i+1] == '&' {
				i += 2
			} else {
				i++
			}
		case ';', '\n', '\r':
			flush()
			if ch == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
		default:
			current.WriteRune(ch)
			i++
		}
	}

	flush()
	return segments
}

func parseBashLineageMutation(cmd string) (sources []string, dest string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 2 {
		return nil, "", false
	}

	switch filepath.Base(parts[0]) {
	case "cp", "mv", "ln":
	default:
		return nil, "", false
	}

	operands := make([]string, 0, len(parts)-1)
	targetDir := ""
	skipNext := false
	endOfOptions := false
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if skipNext {
			skipNext = false
			continue
		}
		if part == "--" {
			endOfOptions = true
			continue
		}
		if isShellRedirectionToken(part) {
			if shellRedirectionConsumesFollowingToken(part) {
				skipNext = true
			}
			continue
		}
		if !endOfOptions && (part == "" || strings.HasPrefix(part, "-")) {
			if dir, consumed, ok := consumeTargetDirectoryFlag(parts[i:]); ok {
				targetDir = strings.Trim(strings.TrimSpace(dir), "\"'`")
				if targetDir == "" {
					return nil, "", false
				}
				i += consumed - 1
				continue
			}
			continue
		}
		operand := strings.Trim(part, "\"'`")
		if operand == "" {
			continue
		}
		operands = append(operands, operand)
	}
	if targetDir != "" {
		if len(operands) == 0 {
			return nil, "", false
		}
		return operands, targetDir, true
	}
	if len(operands) < 2 {
		return nil, "", false
	}
	return operands[:len(operands)-1], operands[len(operands)-1], true
}

func consumeTargetDirectoryFlag(parts []string) (targetDir string, consumed int, ok bool) {
	if len(parts) == 0 {
		return "", 0, false
	}
	part := parts[0]
	if part == "-t" || part == "--target-directory" {
		if len(parts) < 2 {
			return "", 0, false
		}
		return parts[1], 2, true
	}
	if strings.HasPrefix(part, "--target-directory=") {
		return strings.TrimPrefix(part, "--target-directory="), 1, true
	}
	if strings.HasPrefix(part, "-t") && len(part) > 2 && !strings.HasPrefix(part, "--") {
		return strings.TrimLeft(part[2:], "="), 1, true
	}
	if strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "--") {
		for i := 1; i < len(part); i++ {
			if part[i] != 't' {
				continue
			}
			if i+1 < len(part) {
				return strings.TrimLeft(part[i+1:], "="), 1, true
			}
			if len(parts) < 2 {
				return "", 0, false
			}
			return parts[1], 2, true
		}
	}
	return "", 0, false
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
