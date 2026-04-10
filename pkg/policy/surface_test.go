package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type surfaceSpec struct {
	SessionSchemaVersion uint32        `json:"session_schema_version"`
	Verbs                []surfaceItem `json:"verbs"`
	Verdicts             []surfaceItem `json:"verdicts"`
	PostureStates        []surfaceItem `json:"posture_states"`
	ApprovalScopes       []surfaceItem `json:"approval_scopes"`
}

type surfaceItem struct {
	Name string `json:"name"`
	Wire string `json:"wire"`
}

func TestGeneratedSurfaceMatchesSharedSpec(t *testing.T) {
	specPath := filepath.Join("..", "..", "mister-shared", "policy_surface.json")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}

	var spec surfaceSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}

	if got, want := SessionSchemaVersion, spec.SessionSchemaVersion; got != want {
		t.Fatalf("SessionSchemaVersion = %d, want %d", got, want)
	}

	assertWires(t, "verbs", wiresFromSpec(spec.Verbs), stringifyVerbs(AllVerbs))
	assertWires(t, "verdicts", wiresFromSpec(spec.Verdicts), stringifyVerdicts(AllVerdicts))
	assertWires(t, "posture states", wiresFromSpec(spec.PostureStates), stringifyPosture(AllPostureStates))
	assertWires(t, "approval scopes", wiresFromSpec(spec.ApprovalScopes), stringifyScopes(AllApprovalScopes))
}

func TestParseFunctionsRoundTrip(t *testing.T) {
	for _, verb := range AllVerbs {
		got, ok := ParseVerb(string(verb))
		if !ok || got != verb {
			t.Fatalf("ParseVerb(%q) = (%q, %v)", verb, got, ok)
		}
	}

	for _, verdict := range AllVerdicts {
		got, ok := ParseVerdict(string(verdict))
		if !ok || got != verdict {
			t.Fatalf("ParseVerdict(%q) = (%q, %v)", verdict, got, ok)
		}
	}

	for _, posture := range AllPostureStates {
		got, ok := ParsePostureState(string(posture))
		if !ok || got != posture {
			t.Fatalf("ParsePostureState(%q) = (%q, %v)", posture, got, ok)
		}
	}

	for _, scope := range AllApprovalScopes {
		got, ok := ParseApprovalScope(string(scope))
		if !ok || got != scope {
			t.Fatalf("ParseApprovalScope(%q) = (%q, %v)", scope, got, ok)
		}
	}
}

func assertWires(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s count = %d, want %d\n got=%v\nwant=%v", name, len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q\n got=%v\nwant=%v", name, i, got[i], want[i], got, want)
		}
	}
}

func wiresFromSpec(items []surfaceItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Wire)
	}
	return out
}

func stringifyVerbs(values []Verb) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func stringifyVerdicts(values []Verdict) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func stringifyPosture(values []PostureState) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func stringifyScopes(values []ApprovalScope) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}
