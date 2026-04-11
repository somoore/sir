package main

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func mustHooksConfigMap(t testing.TB, builder agent.MapBuilder, sirBinaryPath, mode string) map[string]interface{} {
	t.Helper()

	config, err := builder.GenerateHooksConfigMap(sirBinaryPath, mode)
	if err != nil {
		t.Fatalf("GenerateHooksConfigMap(%q, %q): %v", sirBinaryPath, mode, err)
	}
	return config
}
