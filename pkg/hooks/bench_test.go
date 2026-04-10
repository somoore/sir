package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func BenchmarkMapToolToIntentBashCurl(b *testing.B) {
	l := lease.DefaultLease()
	toolInput := map[string]interface{}{"command": "curl https://api.example.com/collect"}
	for i := 0; i < b.N; i++ {
		_ = MapToolToIntent("Bash", toolInput, l)
	}
}

func BenchmarkEvaluatePayloadNetExternal(b *testing.B) {
	projectRoot := b.TempDir()
	l := lease.DefaultLease()
	payload := &HookPayload{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "curl https://api.example.com/collect",
		},
	}
	for i := 0; i < b.N; i++ {
		state := session.NewState(projectRoot)
		if _, err := evaluatePayload(payload, l, state, projectRoot, agent.NewClaudeAgent()); err != nil {
			b.Fatalf("evaluatePayload: %v", err)
		}
	}
}
