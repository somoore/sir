package posture

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
)

// AppendHookTamperEntry appends a normalized hook tamper entry to the ledger.
func AppendHookTamperEntry(projectRoot, toolName string, f AgentHookFile, decision, reason string, restored bool, diffSummary string) (*ledger.Entry, error) {
	if diffSummary == "" {
		diffSummary = ManagedHookDiffSummary(f)
	}
	entry := &ledger.Entry{
		ToolName:    toolName,
		Verb:        "posture_tamper",
		Target:      f.RelativePath,
		Decision:    decision,
		Reason:      reason,
		Severity:    "HIGH",
		AlertType:   "hook_tamper",
		Agent:       f.AgentID,
		DiffSummary: diffSummary,
		Restored:    restored,
	}
	return entry, ledger.Append(projectRoot, entry)
}

// ManagedHookDiffSummary returns a concise subtree drift summary for a managed
// hook file.
func ManagedHookDiffSummary(f AgentHookFile) string {
	canonical, ok, err := managedHookBaselineBytes(f)
	if err != nil {
		return "baseline unavailable"
	}
	if !ok {
		return "baseline missing"
	}

	current, err := os.ReadFile(f.AbsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "managed hook file missing"
		}
		return "unable to read live hook file"
	}

	liveHooks, liveErr := ExtractManagedSubtree(current, f.managedSubtreeKey())
	canonHooks, canonErr := extractCanonicalManagedSubtreeBytes(canonical, f.managedSubtreeKey())
	if liveErr != nil || canonErr != nil {
		if !bytes.Equal(current, canonical) {
			return "managed subtree modified"
		}
		return ""
	}
	return summarizeJSONDrift(canonHooks, liveHooks)
}

func summarizeJSONDrift(canonical, live []byte) string {
	var canon any
	var cur any
	if err := json.Unmarshal(canonical, &canon); err != nil {
		return "managed subtree modified"
	}
	if err := json.Unmarshal(live, &cur); err != nil {
		return "managed subtree modified"
	}
	return summarizeJSONValueDiff(canon, cur)
}

func summarizeJSONValueDiff(canon, cur any) string {
	switch canonVal := canon.(type) {
	case map[string]any:
		curVal, ok := cur.(map[string]any)
		if !ok {
			return "managed subtree type changed"
		}
		added := make([]string, 0)
		removed := make([]string, 0)
		changed := make([]string, 0)
		for key, canonChild := range canonVal {
			curChild, exists := curVal[key]
			if !exists {
				removed = append(removed, key)
				continue
			}
			if !reflect.DeepEqual(canonChild, curChild) {
				changed = append(changed, key)
			}
		}
		for key := range curVal {
			if _, exists := canonVal[key]; !exists {
				added = append(added, key)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		sort.Strings(changed)
		parts := make([]string, 0, 3)
		if len(removed) > 0 {
			parts = append(parts, "removed "+strings.Join(removed, ", "))
		}
		if len(added) > 0 {
			parts = append(parts, "added "+strings.Join(added, ", "))
		}
		if len(changed) > 0 {
			parts = append(parts, "changed "+strings.Join(changed, ", "))
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, "; ")
	case []any:
		curVal, ok := cur.([]any)
		if !ok {
			return "managed subtree type changed"
		}
		if len(canonVal) != len(curVal) {
			return "managed hook array length changed"
		}
		if !reflect.DeepEqual(canonVal, curVal) {
			return "managed hook array content changed"
		}
		return ""
	default:
		if !reflect.DeepEqual(canon, cur) {
			return "managed subtree value changed"
		}
		return ""
	}
}
