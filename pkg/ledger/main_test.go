package ledger

import (
	"fmt"
	"os"
	"testing"
)

// TestMain gives the package an isolated home so the per-install ledger key
// is never created in the developer's real ~/.sir during tests.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "sir-ledger-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test home: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("HOME", home); err != nil {
		fmt.Fprintf(os.Stderr, "set test HOME: %v\n", err)
		_ = os.RemoveAll(home)
		os.Exit(1)
	}
	_ = os.Unsetenv("SIR_STATE_HOME")
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
