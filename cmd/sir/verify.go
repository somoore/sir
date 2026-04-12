package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/somoore/sir/pkg/core"
)

func cmdVerify() {
	fmt.Println("sir verify")
	fmt.Println()

	manifest, err := core.LoadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
	if manifest == nil {
		fmt.Println("  No binary manifest found at ~/.sir/binary-manifest.json")
		fmt.Println("  Re-run install.sh to generate the manifest.")
		os.Exit(1)
	}

	fmt.Printf("  version:  %s\n", manifest.Version)
	fmt.Printf("  method:   %s\n", manifest.InstallMethod)
	fmt.Printf("  installed: %s\n", manifest.InstalledAt)
	fmt.Println()

	allOK := true

	// Verify sir binary
	sirPath := resolveSirBinaryForVerify(manifest)
	sirHash, err := core.HashFile(sirPath)
	if err != nil {
		fmt.Printf("  sir          ERROR  could not read: %v\n", err)
		allOK = false
	} else if sirHash == manifest.SirSHA256 {
		fmt.Printf("  sir          ok     sha256 matches manifest\n")
	} else {
		fmt.Printf("  sir          MISMATCH\n")
		fmt.Printf("    manifest:  %s\n", manifest.SirSHA256)
		fmt.Printf("    on disk:   %s\n", sirHash)
		allOK = false
	}

	// Verify mister-core binary
	mcPath := resolveMisterCoreForVerify(manifest)
	mcHash, err := core.HashFile(mcPath)
	if err != nil {
		fmt.Printf("  mister-core  ERROR  could not read: %v\n", err)
		allOK = false
	} else if mcHash == manifest.MisterCoreSHA256 {
		fmt.Printf("  mister-core  ok     sha256 matches manifest\n")
	} else {
		fmt.Printf("  mister-core  MISMATCH\n")
		fmt.Printf("    manifest:  %s\n", manifest.MisterCoreSHA256)
		fmt.Printf("    on disk:   %s\n", mcHash)
		allOK = false
	}

	fmt.Println()
	if allOK {
		fmt.Println("  Binaries verified against install-time manifest.")
	} else {
		fmt.Println("  WARNING: one or more binaries do not match the install-time manifest.")
		fmt.Println("  This may indicate tampering. Re-run install.sh to rebuild from source.")
		os.Exit(1)
	}
}

// resolveSirBinaryForVerify returns the path to the sir binary to verify.
// Prefers the manifest path if the file exists, falls back to the running binary.
func resolveSirBinaryForVerify(m *core.BinaryManifest) string {
	if m.SirPath != "" {
		if _, err := os.Stat(m.SirPath); err == nil {
			return m.SirPath
		}
	}
	if exePath, err := os.Executable(); err == nil {
		return exePath
	}
	return "sir"
}

// resolveMisterCoreForVerify returns the path to the mister-core binary to verify.
// Prefers the manifest path if the file exists, falls back to PATH lookup.
func resolveMisterCoreForVerify(m *core.BinaryManifest) string {
	if m.MisterCorePath != "" {
		if _, err := os.Stat(m.MisterCorePath); err == nil {
			return m.MisterCorePath
		}
	}
	if path, err := exec.LookPath("mister-core"); err == nil {
		return path
	}
	return "mister-core"
}
