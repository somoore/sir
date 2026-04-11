package agent

import (
	"strings"
	"testing"
)

func TestBaseGenerateHooksConfigMap_InvalidLayoutReturnsError(t *testing.T) {
	spec := &AgentSpec{
		ConfigStrategy: ConfigStrategy{
			Layout: ConfigLayout("flat"),
		},
	}

	_, err := baseGenerateHooksConfigMap(spec, "/usr/local/bin/sir", "guard")
	if err == nil {
		t.Fatal("baseGenerateHooksConfigMap unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "unsupported config layout") {
		t.Fatalf("unexpected error: %v", err)
	}
}
