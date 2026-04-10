package hooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPackageName_Pip(t *testing.T) {
	tests := []struct {
		cmd      string
		expected string
	}{
		{"pip install requests", "requests"},
		{"pip install foo==1.2.3", "foo"},
		{"pip install foo>=2.0", "foo"},
		{"pip install -r requirements.txt", ""},
		{"pip install --upgrade requests", "requests"},
		{"pip3 install flask", "flask"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			got := extractPackageName(tc.cmd, "pip")
			if got != tc.expected {
				t.Errorf("extractPackageName(%q, pip) = %q, want %q", tc.cmd, got, tc.expected)
			}
		})
	}
}

func TestExtractPackageName_Npm(t *testing.T) {
	tests := []struct {
		cmd      string
		expected string
	}{
		{"npm install express", "express"},
		{"npm install", ""},
		{"npm i lodash@4.17", "lodash"},
		{"npm install --save-dev jest", "jest"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			got := extractPackageName(tc.cmd, "npm")
			if got != tc.expected {
				t.Errorf("extractPackageName(%q, npm) = %q, want %q", tc.cmd, got, tc.expected)
			}
		})
	}
}

func TestExtractPackageName_Cargo(t *testing.T) {
	tests := []struct {
		cmd      string
		expected string
	}{
		{"cargo add serde", "serde"},
		{"cargo add tokio --features full", "tokio"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			got := extractPackageName(tc.cmd, "cargo")
			if got != tc.expected {
				t.Errorf("extractPackageName(%q, cargo) = %q, want %q", tc.cmd, got, tc.expected)
			}
		})
	}
}

func TestIsPackageInLockfile_Found_Npm(t *testing.T) {
	tmpDir := t.TempDir()
	lockContent := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2"
    }
  },
  "dependencies": {
    "express": {
      "version": "4.18.2"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if !isPackageInLockfile(tmpDir, "npm", "express") {
		t.Error("expected express to be found in package-lock.json")
	}
}

func TestIsPackageInLockfile_NotFound_Npm(t *testing.T) {
	tmpDir := t.TempDir()
	lockContent := `{"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "4.18.2"}}}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if isPackageInLockfile(tmpDir, "npm", "evil-pkg") {
		t.Error("evil-pkg should not be found in package-lock.json")
	}
}

func TestIsPackageInLockfile_NoLockfile(t *testing.T) {
	tmpDir := t.TempDir()
	// No lockfile exists — greenfield project, skip check (return true = allow)
	if !isPackageInLockfile(tmpDir, "npm", "any-package") {
		t.Error("when no lockfile exists, should return true (greenfield project, skip check)")
	}
}

func TestIsPackageInLockfile_Found_Pip(t *testing.T) {
	tmpDir := t.TempDir()
	requirementsContent := "requests==2.28.0\nflask>=2.0\nclick\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if !isPackageInLockfile(tmpDir, "pip", "requests") {
		t.Error("expected requests to be found in requirements.txt")
	}
}

func TestIsPackageInLockfile_Pip_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	requirementsContent := "requests==2.28.0\nflask>=2.0\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if isPackageInLockfile(tmpDir, "pip", "evil-pkg") {
		t.Error("evil-pkg should not be found in requirements.txt")
	}
}

func TestIsPackageInLockfile_Cargo(t *testing.T) {
	tmpDir := t.TempDir()
	cargoLock := `[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "myapp"
version = "0.1.0"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Cargo.lock"), []byte(cargoLock), 0o644); err != nil {
		t.Fatal(err)
	}

	if !isPackageInLockfile(tmpDir, "cargo", "serde") {
		t.Error("expected serde to be found in Cargo.lock")
	}
	if isPackageInLockfile(tmpDir, "cargo", "evil-crate") {
		t.Error("evil-crate should not be found in Cargo.lock")
	}
}

func TestIsInstallCommand(t *testing.T) {
	tests := []struct {
		cmd       string
		isInstall bool
		manager   string
	}{
		// pip variants (3 prefixes)
		{"pip install requests", true, "pip"},
		{"pip install requests==2.31.0", true, "pip"},
		{"pip install -r requirements.txt", true, "pip"},
		{"pip3 install flask", true, "pip"},
		{"python -m pip install django", true, "pip"},
		{"python3 -m pip install numpy", true, "pip"},

		// npm variants (2 prefixes)
		{"npm install lodash", true, "npm"},
		{"npm install --save-dev jest", true, "npm"},
		{"npm i express", true, "npm"},
		{"npm i -D typescript", true, "npm"},

		// yarn
		{"yarn add react", true, "yarn"},
		{"yarn add -D @types/node", true, "yarn"},

		// pnpm
		{"pnpm add vue", true, "pnpm"},
		{"pnpm add -D vitest", true, "pnpm"},

		// bun
		{"bun add elysia", true, "bun"},
		{"bun add -d @types/bun", true, "bun"},

		// cargo
		{"cargo add serde", true, "cargo"},
		{"cargo add tokio --features full", true, "cargo"},

		// go
		{"go get golang.org/x/tools", true, "go"},
		{"go get -u ./...", true, "go"},
		{"go get github.com/gin-gonic/gin", true, "go"},

		// gem
		{"gem install rails", true, "gem"},
		{"gem install bundler --version 2.4", true, "gem"},

		// uv
		{"uv add httpx", true, "uv"},

		// poetry
		{"poetry add pendulum", true, "poetry"},
		{"poetry add sqlalchemy", true, "poetry"},
		{"poetry add --dev pytest", true, "poetry"},

		// NOT install commands
		{"npx create-react-app", false, ""},
		{"npm test", false, ""},
		{"npm run build", false, ""},
		{"go test ./...", false, ""},
		{"go build ./cmd/sir", false, ""},
		{"cargo build", false, ""},
		{"cargo test", false, ""},
		{"pip --version", false, ""},
		{"pip list", false, ""},
		{"yarn start", false, ""},
		{"ls -la", false, ""},
		{"git commit -m 'test'", false, ""},
		{"curl https://example.com", false, ""},
		{"make install", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			isInstall, manager := IsInstallCommand(tt.cmd)
			if isInstall != tt.isInstall {
				t.Errorf("IsInstallCommand(%q) = %v, want %v", tt.cmd, isInstall, tt.isInstall)
			}
			if isInstall && manager != tt.manager {
				t.Errorf("IsInstallCommand(%q) manager = %q, want %q", tt.cmd, manager, tt.manager)
			}
		})
	}
}

func TestLockfileForManager(t *testing.T) {
	tests := []struct {
		manager  string
		expected []string
	}{
		{"pip", []string{"requirements.txt", "requirements-dev.txt", "Pipfile.lock"}},
		{"npm", []string{"package-lock.json"}},
		{"yarn", []string{"yarn.lock"}},
		{"pnpm", []string{"pnpm-lock.yaml"}},
		{"bun", []string{"bun.lockb"}},
		{"cargo", []string{"Cargo.lock"}},
		{"go", []string{"go.sum"}},
		{"gem", []string{"Gemfile.lock"}},
		{"uv", []string{"uv.lock"}},
		{"poetry", []string{"poetry.lock"}},
		{"unknown", nil},
	}

	for _, tt := range tests {
		t.Run(tt.manager, func(t *testing.T) {
			result := LockfileForManager(tt.manager)
			if len(result) == 0 && len(tt.expected) == 0 {
				return // both nil/empty
			}
			if len(result) == 0 {
				t.Errorf("LockfileForManager(%q) returned empty, want %v", tt.manager, tt.expected)
				return
			}
			// At minimum, the primary lockfile must be present
			if result[0] != tt.expected[0] {
				t.Errorf("LockfileForManager(%q) primary = %q, want %q",
					tt.manager, result[0], tt.expected[0])
			}
		})
	}
}

func TestHashSentinelFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test sentinel files
	files := map[string]string{
		"hooks.json":    `{"hooks": []}`,
		"settings.json": `{"settings": {}}`,
		"CLAUDE.md":     "# Project Instructions",
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
	}

	sentinels := []string{"hooks.json", "settings.json", "CLAUDE.md", "nonexistent.txt"}
	hashes := HashSentinelFiles(tmpDir, sentinels)

	// Existing files should have hashes
	for name := range files {
		if hashes[name] == "" {
			t.Errorf("expected hash for %s", name)
		}
	}

	// Non-existent file should have empty hash
	if hashes["nonexistent.txt"] != "" {
		t.Error("expected empty hash for non-existent file")
	}

	// Verify hash changes when content changes
	os.WriteFile(filepath.Join(tmpDir, "hooks.json"), []byte(`{"hooks": [{"malicious": true}]}`), 0o644)
	newHashes := HashSentinelFiles(tmpDir, sentinels)
	if newHashes["hooks.json"] == hashes["hooks.json"] {
		t.Error("hash should change after file modification")
	}
	if newHashes["settings.json"] != hashes["settings.json"] {
		t.Error("hash should not change for unmodified file")
	}
}

func TestCompareSentinelHashes(t *testing.T) {
	tests := []struct {
		name          string
		before        map[string]string
		after         map[string]string
		expectedCount int
	}{
		{
			name: "no changes",
			before: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "def456",
			},
			after: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "def456",
			},
			expectedCount: 0,
		},
		{
			name: "one file changed",
			before: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "def456",
			},
			after: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "changed",
			},
			expectedCount: 1,
		},
		{
			name: "file appeared (was empty, now has content)",
			before: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "",
			},
			after: map[string]string{
				"file1.txt": "abc123",
				"file2.txt": "new-content",
			},
			expectedCount: 1,
		},
		{
			name: "multiple changes",
			before: map[string]string{
				"a.txt": "hash1",
				"b.txt": "hash2",
				"c.txt": "hash3",
			},
			after: map[string]string{
				"a.txt": "changed1",
				"b.txt": "hash2",
				"c.txt": "changed3",
			},
			expectedCount: 2,
		},
		{
			name: "file created during install",
			before: map[string]string{
				"existing.txt": "hash1",
			},
			after: map[string]string{
				"existing.txt": "hash1",
				"new-file.txt": "hash2",
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := CompareSentinelHashes(tt.before, tt.after)
			if len(changed) != tt.expectedCount {
				t.Errorf("expected %d changed files, got %d: %v",
					tt.expectedCount, len(changed), changed)
			}
		})
	}
}

func TestDiffLockfile(t *testing.T) {
	tests := []struct {
		name       string
		before     string
		after      string
		addedCount int
	}{
		{
			name:       "package added",
			before:     "express@4.18.0\nlodash@4.17.21\n",
			after:      "express@4.18.0\nlodash@4.17.21\nmalicious-pkg@1.0.0\n",
			addedCount: 1,
		},
		{
			name:       "multiple packages added",
			before:     "line1\nline2\nline3\n",
			after:      "line1\nline2\nline3\nline4\nline5\n",
			addedCount: 2,
		},
		{
			name:       "no change",
			before:     "express@4.18.0\nlodash@4.17.21\n",
			after:      "express@4.18.0\nlodash@4.17.21\n",
			addedCount: 0,
		},
		{
			name:       "package removed (no additions)",
			before:     "express@4.18.0\nlodash@4.17.21\n",
			after:      "express@4.18.0\n",
			addedCount: 0,
		},
		{
			name:       "version updated counts as added",
			before:     "express@4.18.0\n",
			after:      "express@4.19.0\n",
			addedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added := DiffLockfile(tt.before, tt.after)
			if len(added) != tt.addedCount {
				t.Errorf("expected %d added lines, got %d: %v",
					tt.addedCount, len(added), added)
			}
		})
	}
}
