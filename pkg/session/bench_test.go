package session

import (
	"testing"
	"time"
)

func BenchmarkUpdateSessionMutation(b *testing.B) {
	projectRoot := b.TempDir()
	state := NewState(projectRoot)
	if err := state.Save(); err != nil {
		b.Fatalf("save initial session: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Update(projectRoot, func(s *State) error {
			s.MarkUntrustedRead()
			s.ClearUntrustedRead()
			s.LastToolCallAt = time.Unix(int64(i), 0)
			s.PendingInjectionAlert = false
			return nil
		}); err != nil {
			b.Fatalf("session.Update: %v", err)
		}
	}
}
