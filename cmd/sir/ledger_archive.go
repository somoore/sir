package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func cmdLogLifecycle(projectRoot string, args []string) {
	if len(args) == 0 {
		cmdLog(projectRoot, false)
		return
	}
	switch args[0] {
	case "verify":
		cmdLog(projectRoot, true)
	case "archive":
		cmdLogArchive(projectRoot, args[1:])
	case "export":
		cmdLogExport(projectRoot, args[1:])
	default:
		fatal("usage: sir log [verify|archive|export]")
	}
}

func cmdLogArchive(projectRoot string, args []string) {
	prune := false
	yes := false
	output := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--prune":
			prune = true
		case "--yes", "-y":
			yes = true
		case "--output", "-o":
			if i+1 >= len(args) {
				fatal("--output requires a path")
			}
			output = args[i+1]
			i++
		default:
			fatal("unknown flag: %s", args[i])
		}
	}
	count, err := ledger.Verify(projectRoot)
	if err != nil {
		fatal("ledger chain is broken at entry %d: %v", count, err)
	}
	source := ledger.LedgerPath(projectRoot)
	if _, err := os.Stat(source); os.IsNotExist(err) {
		fmt.Println("Ledger is empty; nothing to archive.")
		return
	}
	if output == "" {
		output = filepath.Join(session.StateDir(projectRoot), "archives", "ledger-"+time.Now().UTC().Format("20060102-150405")+".jsonl")
	}
	if !yes && prune {
		fmt.Printf("Archive and prune active ledger? Archive: %s [y/N] ", output)
		var confirm string
		fmt.Scanln(&confirm)
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Cancelled. No changes made.")
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		fatal("create archive dir: %v", err)
	}
	if err := copyFile(output, source, 0o600); err != nil {
		fatal("archive ledger: %v", err)
	}
	sum, err := sha256File(output)
	if err != nil {
		fatal("hash archive: %v", err)
	}
	manifest := output + ".sha256"
	if err := os.WriteFile(manifest, []byte(sum+"  "+filepath.Base(output)+"\n"), 0o600); err != nil {
		fatal("write archive checksum: %v", err)
	}
	if prune {
		if err := os.WriteFile(source, nil, 0o600); err != nil {
			fatal("prune active ledger: %v", err)
		}
		ledger.Append(projectRoot, &ledger.Entry{
			Verb:     "ledger_archive",
			Target:   output,
			Decision: "allow",
			Reason:   fmt.Sprintf("archived %d entries; sha256=%s", count, sum),
		})
	}
	fmt.Printf("Archived %d ledger entries to %s\n", count, output)
	fmt.Printf("Checksum written to %s\n", manifest)
}

func cmdLogExport(projectRoot string, args []string) {
	output := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output", "-o":
			if i+1 >= len(args) {
				fatal("--output requires a path")
			}
			output = args[i+1]
			i++
		default:
			fatal("unknown flag: %s", args[i])
		}
	}
	if output == "" {
		output = filepath.Join(session.StateDir(projectRoot), "exports", "ledger-export-"+time.Now().UTC().Format("20060102-150405")+".jsonl")
	}
	if _, err := ledger.Verify(projectRoot); err != nil {
		fatal("ledger chain is broken: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		fatal("create export dir: %v", err)
	}
	if err := copyFile(output, ledger.LedgerPath(projectRoot), 0o600); err != nil {
		fatal("export ledger: %v", err)
	}
	fmt.Printf("Exported ledger to %s\n", output)
}

func copyFile(dst, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		if closeErr := out.Close(); closeErr != nil {
			return fmt.Errorf("copy %s to %s: %w (close also failed: %v)", src, dst, err, closeErr)
		}
		return err
	}
	return out.Close()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
