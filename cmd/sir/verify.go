package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/somoore/sir/pkg/core"
)

type binaryIntegrityStatus struct {
	manifest       *core.BinaryManifest
	sirPath        string
	sirHash        string
	sirErr         error
	misterCorePath string
	misterCoreHash string
	misterCoreErr  error
}

func cmdVerify() {
	fmt.Println("sir verify")
	fmt.Println()

	status, err := inspectBinaryIntegrity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
	if status == nil {
		fmt.Println("  No binary manifest found at ~/.sir/binary-manifest.json")
		fmt.Println("  Reinstall sir to generate the manifest. For source trees, run 'make install' or './install.sh'.")
		os.Exit(1)
	}
	manifest := status.manifest

	fmt.Printf("  version:  %s\n", manifest.Version)
	fmt.Printf("  method:   %s\n", manifest.InstallMethod)
	fmt.Printf("  installed: %s\n", manifest.InstalledAt)
	fmt.Println()

	allOK := true

	// Verify sir binary
	if status.sirErr != nil {
		fmt.Printf("  sir          ERROR  could not read: %v\n", status.sirErr)
		allOK = false
	} else if status.sirHash == manifest.SirSHA256 {
		fmt.Printf("  sir          ok     sha256 matches manifest\n")
	} else {
		fmt.Printf("  sir          MISMATCH\n")
		fmt.Printf("    manifest:  %s\n", manifest.SirSHA256)
		fmt.Printf("    on disk:   %s\n", status.sirHash)
		allOK = false
	}

	// Verify mister-core binary
	if status.misterCoreErr != nil {
		fmt.Printf("  mister-core  ERROR  could not read: %v\n", status.misterCoreErr)
		allOK = false
	} else if status.misterCoreHash == manifest.MisterCoreSHA256 {
		fmt.Printf("  mister-core  ok     sha256 matches manifest\n")
	} else {
		fmt.Printf("  mister-core  MISMATCH\n")
		fmt.Printf("    manifest:  %s\n", manifest.MisterCoreSHA256)
		fmt.Printf("    on disk:   %s\n", status.misterCoreHash)
		allOK = false
	}

	fmt.Println()
	if allOK {
		fmt.Println("  Binaries verified against install-time manifest.")
	} else {
		fmt.Println("  WARNING: one or more binaries do not match the install-time manifest.")
		fmt.Println("  This may indicate tampering. Reinstall sir to refresh ~/.sir/binary-manifest.json.")
		fmt.Println("  For source trees, run 'make install' or './install.sh'.")
		os.Exit(1)
	}
}

func inspectBinaryIntegrity() (*binaryIntegrityStatus, error) {
	manifest, err := core.LoadManifest()
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, nil
	}

	status := &binaryIntegrityStatus{
		manifest:       manifest,
		sirPath:        resolveSirBinaryForVerify(manifest),
		misterCorePath: resolveMisterCoreForVerify(manifest),
	}
	status.sirHash, status.sirErr = core.HashFile(status.sirPath)
	status.misterCoreHash, status.misterCoreErr = core.HashFile(status.misterCorePath)
	return status, nil
}

func (s *binaryIntegrityStatus) allOK() bool {
	if s == nil {
		return false
	}
	return s.sirErr == nil &&
		s.sirHash == s.manifest.SirSHA256 &&
		s.misterCoreErr == nil &&
		s.misterCoreHash == s.manifest.MisterCoreSHA256
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
