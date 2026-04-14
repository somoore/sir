package classify

import (
	"strings"
	"testing"
)

func TestExtractMCPURLs(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  []string
	}{
		{
			"nil input",
			nil,
			nil,
		},
		{
			"no url",
			map[string]interface{}{"query": "select 1"},
			nil,
		},
		{
			"http url in top-level field",
			map[string]interface{}{"url": "https://api.example.com/v1"},
			[]string{"https://api.example.com/v1"},
		},
		{
			"arbitrary key name",
			map[string]interface{}{"destination": "http://example.com/x"},
			[]string{"http://example.com/x"},
		},
		{
			"nested map",
			map[string]interface{}{
				"options": map[string]interface{}{"endpoint": "https://a.example/b"},
			},
			[]string{"https://a.example/b"},
		},
		{
			"array of urls",
			map[string]interface{}{
				"targets": []interface{}{"https://a.example", "https://b.example"},
			},
			[]string{"https://a.example", "https://b.example"},
		},
		{
			"non-http scheme ignored",
			map[string]interface{}{
				"fs":  "file:///etc/passwd",
				"git": "ssh://git@github.com/x",
				"db":  "postgres://host/db",
			},
			nil,
		},
		{
			"empty and overlong strings skipped",
			map[string]interface{}{
				"u1": "",
				"u2": "https://" + strings.Repeat("a", 2500) + ".example",
			},
			nil,
		},
		{
			"known limitation: field-split url is not detected",
			map[string]interface{}{
				"host": "evil.com",
				"path": "/steal",
			},
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractMCPURLs(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d want=%d: got=%v want=%v", len(got), len(tc.want), got, tc.want)
			}
			wantSet := make(map[string]bool, len(tc.want))
			for _, w := range tc.want {
				wantSet[w] = true
			}
			for _, g := range got {
				if !wantSet[g] {
					t.Errorf("unexpected URL %q in result", g)
				}
			}
		})
	}
}

func TestExtractMCPURLs_DepthLimit(t *testing.T) {
	deep := interface{}("https://deep.example")
	for i := 0; i < 20; i++ {
		deep = map[string]interface{}{"next": deep}
	}
	input, ok := deep.(map[string]interface{})
	if !ok {
		t.Fatal("setup: not a map")
	}
	got := ExtractMCPURLs(input)
	if len(got) != 0 {
		t.Fatalf("expected depth limit to drop URL, got %v", got)
	}
}
