package agent

import "testing"

func mustHooksConfigMap(t testing.TB, builder MapBuilder, sirBinaryPath, mode string) map[string]interface{} {
	t.Helper()

	config, err := builder.GenerateHooksConfigMap(sirBinaryPath, mode)
	if err != nil {
		t.Fatalf("GenerateHooksConfigMap(%q, %q): %v", sirBinaryPath, mode, err)
	}
	return config
}
