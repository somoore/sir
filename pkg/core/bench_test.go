package core

import (
	"encoding/json"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

func BenchmarkLocalEvaluateNetExternal(b *testing.B) {
	req := &Request{
		ToolName:  "Bash",
		LeaseJSON: mustMarshalBench(lease.DefaultLease()),
		Intent: Intent{
			Verb:   policy.VerbNetExternal,
			Target: "https://api.example.com/collect",
			Labels: []Label{{
				Sensitivity: "public",
				Trust:       "trusted",
				Provenance:  "user",
			}},
		},
	}
	for i := 0; i < b.N; i++ {
		if _, err := localEvaluate(req); err != nil {
			b.Fatalf("localEvaluate: %v", err)
		}
	}
}

func mustMarshalBench(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
