package telemetry

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func BenchmarkEmitBuffered(b *testing.B) {
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	ex := newExporterWithConfig("", "session-bench", "claude", "Claude Code", "http://collector.test", client, 256, 2)
	b.Cleanup(ex.Shutdown)

	ev := LogEvent{
		Timestamp:   time.Unix(1_700_000_000, 0),
		ToolName:    "Bash",
		Verb:        "net_external",
		Verdict:     "deny",
		Target:      "api.example.com",
		Reason:      "benchmark",
		LedgerIndex: 7,
		LedgerHash:  "abc123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ex.Emit(ev)
	}
}
