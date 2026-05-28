package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/secretview"
)

// maxSecretViewBytes caps how much of a file the redacted viewer will read.
const maxSecretViewBytes = 1 << 20 // 1 MiB

func cmdSecret(projectRoot string, args []string) {
	if len(args) < 1 || args[0] != "view" {
		fatal("usage: sir secret view <path> [--json]")
	}
	rest := args[1:]
	asJSON := false
	path := ""
	for _, arg := range rest {
		switch arg {
		case "--json":
			asJSON = true
		default:
			if path != "" {
				fatal("usage: sir secret view <path> [--json]")
			}
			path = arg
		}
	}
	if path == "" {
		fatal("usage: sir secret view <path> [--json]")
	}
	cmdSecretView(projectRoot, path, asJSON)
}

// cmdSecretView prints a redacted, presence-only view of a sensitive file:
// key names with masked values, never the values themselves. This is the safe
// path a sensitive-read block points the developer (or agent) to.
func cmdSecretView(projectRoot, path string, asJSON bool) {
	// Resolve symlinks before reading so the view reflects the real target,
	// consistent with sir's path-classification rule.
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}

	info, err := os.Stat(resolved)
	if err != nil {
		fatal("cannot read %q: %v", path, err)
	}
	if info.IsDir() {
		fatal("%q is a directory", path)
	}

	f, err := os.Open(resolved)
	if err != nil {
		fatal("cannot open %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	content := make([]byte, maxSecretViewBytes)
	n, _ := f.Read(content)
	content = content[:n]

	view := secretview.Redact(filepath.Base(resolved), content)

	// Record that a redacted view occurred. The ledger never receives a value
	// or key name here — only the fact and counts — so the audit trail shows a
	// redacted view was used instead of a raw read.
	_ = ledger.Append(projectRoot, &ledger.Entry{
		ToolName: "sir-cli",
		Verb:     "secret_view",
		Target:   filepath.Base(path),
		Decision: "allow",
		Reason:   fmt.Sprintf("redacted secret view: %d keys, %d credential-like", len(view.Entries), view.CredentialHits),
	})

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(view); err != nil {
			fatal("encode view: %v", err)
		}
		return
	}
	renderSecretView(path, view)
}

func renderSecretView(path string, v secretview.View) {
	fmt.Printf("sir secret view %s  (redacted — values never shown)\n\n", path)
	if v.Kind == "env" {
		fmt.Printf("  %d keys", len(v.Entries))
		if v.CommentLines == 1 {
			fmt.Printf(", 1 comment line")
		} else if v.CommentLines > 1 {
			fmt.Printf(", %d comment lines", v.CommentLines)
		}
		if v.CredentialHits > 0 {
			fmt.Printf(", %d credential-like", v.CredentialHits)
		}
		fmt.Println()
		fmt.Println()
		width := 0
		for _, e := range v.Entries {
			if len(e.Key) > width {
				width = len(e.Key)
			}
		}
		for _, e := range v.Entries {
			status := "empty"
			if e.Present {
				status = fmt.Sprintf("present (%d chars)", e.ValueLen)
			}
			class := ""
			if e.Class != "" {
				class = "  [" + e.Class + "]"
			}
			fmt.Printf("  %-*s  %s%s\n", width, e.Key, status, class)
		}
		fmt.Println()
		fmt.Println("  Values are redacted. A raw read requires explicit approval.")
		return
	}

	fmt.Printf("  opaque file: %d bytes, %d lines\n", v.Bytes, v.Lines)
	if v.CredentialHits > 0 {
		fmt.Printf("  %d credential-like pattern(s) detected (redacted)\n", v.CredentialHits)
	}
	fmt.Println()
	fmt.Println("  Values are redacted. A raw read requires explicit approval.")
}
