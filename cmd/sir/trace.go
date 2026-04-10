package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func cmdTrace(projectRoot string) {
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	if len(entries) == 0 {
		fmt.Println("Ledger is empty. No decisions to trace.")
		return
	}

	// Load session state for metadata header
	sess, _ := session.Load(projectRoot)

	// Write to temp file
	outPath := fmt.Sprintf("/tmp/sir-trace-%d.html", time.Now().Unix())
	if err := os.WriteFile(outPath, []byte(renderTraceHTML(entries, sess)), 0o644); err != nil {
		fatal("write trace file: %v", err)
	}
	fmt.Printf("Trace written to %s\n", outPath)

	// Open in browser
	var openCmd string
	if runtime.GOOS == "darwin" {
		openCmd = "open"
	} else {
		openCmd = "xdg-open"
	}
	if err := exec.Command(openCmd, outPath).Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser: %v\nOpen %s manually.\n", err, outPath)
	}
}
