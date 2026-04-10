package ledger

import (
	"os"
	"testing"

	"github.com/somoore/sir/pkg/session"
)

func BenchmarkVerifyLargeLedger(b *testing.B) {
	projectRoot := b.TempDir()
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		b.Fatalf("mkdir state dir: %v", err)
	}
	for i := 0; i < 250; i++ {
		if err := Append(projectRoot, &Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "go test ./...",
			Decision: "allow",
			Reason:   "within lease boundary",
		}); err != nil {
			b.Fatalf("append: %v", err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(projectRoot); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}
