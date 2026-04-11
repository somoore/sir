package hooks

import (
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
		source, dest, ok := parseBashLineageMutation(segment)
		if !ok {
			continue
		}
		sourcePath := ResolveTarget(projectRoot, source)
		destPath := ResolveTarget(projectRoot, dest)
		mirrorDerivedLineage(state, sourcePath, destPath)
	}
}

func parseBashLineageMutation(cmd string) (source, dest string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 3 {
		return "", "", false
	}

	switch filepath.Base(parts[0]) {
	case "cp", "mv", "ln":
	default:
		return "", "", false
	}

	operands := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		if part == "" || strings.HasPrefix(part, "-") {
			continue
		}
		operands = append(operands, strings.Trim(part, "\"'`"))
	}
	if len(operands) < 2 {
		return "", "", false
	}
	return operands[0], operands[len(operands)-1], true
}

func mirrorDerivedLineage(state *session.State, sourcePath, destPath string) {
	if sourcePath == "" || destPath == "" || sourcePath == destPath {
		return
	}
	if state.DerivedFileLineage == nil {
		state.DerivedFileLineage = make(map[string]session.DerivedPathRecord)
	}
	record, ok := state.DerivedFileLineage[sourcePath]
	if !ok || len(record.Labels) == 0 {
		return
	}
	record.UpdatedAt = time.Now()
	state.DerivedFileLineage[destPath] = record
}
