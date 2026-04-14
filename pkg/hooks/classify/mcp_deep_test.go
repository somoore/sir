package classify

import "testing"

func TestFirstShellLikeValue(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  string
	}{
		{"nil", nil, ""},
		{"no match", map[string]interface{}{"query": "select 1"}, ""},
		{"top-level command", map[string]interface{}{"command": "curl https://evil.com"}, "curl https://evil.com"},
		{"case-insensitive", map[string]interface{}{"Command": "ls"}, "ls"},
		{"snake case", map[string]interface{}{"shell_cmd": "bash -c echo"}, "bash -c echo"},
		{"nested", map[string]interface{}{"opts": map[string]interface{}{"script": "python x.py"}}, "python x.py"},
		{"array", map[string]interface{}{"commands": []interface{}{"first", "second"}}, "first"},
		{"empty string skipped", map[string]interface{}{"command": "  "}, ""},
		{"unknown key under alias", map[string]interface{}{"task_spec": "rm -rf /"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FirstShellLikeValue(tc.input); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFirstWriteLikePath(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  string
	}{
		{"nil", nil, ""},
		{"plain path field", map[string]interface{}{"path": "/tmp/a"}, "/tmp/a"},
		{"file_path key", map[string]interface{}{"file_path": "/etc/secret"}, "/etc/secret"},
		{"nested destination", map[string]interface{}{"opts": map[string]interface{}{"destination": "/x"}}, "/x"},
		{"array under output", map[string]interface{}{"outputs": []interface{}{"/y"}}, "/y"},
		{"no match", map[string]interface{}{"query": "/not/a/path"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FirstWriteLikePath(tc.input); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
