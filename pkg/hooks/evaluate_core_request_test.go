package hooks

import (
	"errors"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func TestBuildCoreRequest_MarshalLeaseFailureReturnsError(t *testing.T) {
	origMarshal := jsonMarshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() {
		jsonMarshal = origMarshal
	})

	_, err := buildCoreRequest(
		t.TempDir(),
		&HookPayload{ToolName: "Read"},
		Intent{Verb: "read_ref", Target: "src/main.go"},
		lease.DefaultLease(),
		session.NewState(t.TempDir()),
		core.Label{Sensitivity: "public", Trust: "trusted", Provenance: "user"},
	)
	if err == nil {
		t.Fatal("buildCoreRequest unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "marshal lease") {
		t.Fatalf("expected marshal lease detail, got %v", err)
	}
}

func TestEvaluatePolicy_BuildCoreRequestError(t *testing.T) {
	origMarshal := jsonMarshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() {
		jsonMarshal = origMarshal
	})

	projectRoot := t.TempDir()
	_, err := evaluatePolicy(
		projectRoot,
		&HookPayload{ToolName: "Read"},
		Intent{Verb: "read_ref", Target: "src/main.go"},
		lease.DefaultLease(),
		session.NewState(projectRoot),
		core.Label{Sensitivity: "public", Trust: "trusted", Provenance: "user"},
	)
	if err == nil {
		t.Fatal("evaluatePolicy unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "build core request") {
		t.Fatalf("expected build core request detail, got %v", err)
	}
	if !strings.Contains(err.Error(), "marshal lease") {
		t.Fatalf("expected marshal lease detail, got %v", err)
	}
}
