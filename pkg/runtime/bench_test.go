package runtime

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func BenchmarkBuildDarwinProfile(b *testing.B) {
	homeDir := b.TempDir()
	projectRoot := b.TempDir()
	b.Setenv("HOME", homeDir)

	opts := Options{Agent: agent.NewClaudeAgent()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BuildDarwinProfile(projectRoot, opts); err != nil {
			b.Fatalf("BuildDarwinProfile: %v", err)
		}
	}
}

func BenchmarkProxyHostMatch(b *testing.B) {
	proxy := &LocalProxy{
		allowlist: buildRuntimeAllowlist([]string{
			"api.anthropic.com",
			"openai.com",
			"localhost",
		}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !proxy.isAllowed("api.anthropic.com", "443") {
			b.Fatal("expected destination to stay allowlisted")
		}
	}
}
