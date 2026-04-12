// Package core implements the MSTR/1 protocol bridge to mister-core.
// It executes the mister-core binary and communicates via stdin/stdout.
package core

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/somoore/sir/pkg/policy"
)

// misterCoreIntegrity caches the result of the mister-core binary integrity
// check. The hash is computed once per process via sync.Once — the ~550KB
// binary is hashed on the first Evaluate() call and the result is reused for
// the process lifetime. If the binary changes mid-session, the next sir
// invocation (which is a new process) catches it.
var misterCoreIntegrity struct {
	once sync.Once
	err  error // nil = verified or no manifest; non-nil = mismatch
}

// verifyMisterCoreOnce checks mister-core binary integrity against the
// install-time manifest. Cached via sync.Once per process.
//
// Returns nil if: manifest doesn't exist (pre-upgrade), or hash matches.
// Returns error if: manifest exists and hash doesn't match.
func verifyMisterCoreOnce(binaryPath string) error {
	misterCoreIntegrity.once.Do(func() {
		manifest, err := LoadManifest()
		if err != nil {
			misterCoreIntegrity.err = fmt.Errorf("load manifest: %w", err)
			return
		}
		if manifest == nil {
			// No manifest — pre-upgrade install, skip check.
			return
		}
		if manifest.MisterCoreSHA256 == "" {
			// Manifest exists but has no mister-core hash — skip.
			return
		}
		diskHash, err := HashFile(binaryPath)
		if err != nil {
			misterCoreIntegrity.err = fmt.Errorf("hash mister-core: %w", err)
			return
		}
		if diskHash != manifest.MisterCoreSHA256 {
			misterCoreIntegrity.err = fmt.Errorf(
				"mister-core binary integrity mismatch (manifest: %s, disk: %s)",
				manifest.MisterCoreSHA256[:16]+"...", diskHash[:16]+"...",
			)
		}
	})
	return misterCoreIntegrity.err
}

// ResetIntegrityCache clears the cached integrity check result.
// Exported for testing only.
func ResetIntegrityCache() {
	misterCoreIntegrity = struct {
		once sync.Once
		err  error
	}{}
}

// Evaluate sends a request to mister-core and returns the verdict.
// If mister-core is not available, it falls back to local policy evaluation.
func Evaluate(req *Request) (*Response, error) {
	path, err := exec.LookPath(CoreBinaryPath)
	if err != nil {
		return localEvaluate(req)
	}

	if err := verifyMisterCoreOnce(path); err != nil {
		return &Response{
			Decision: policy.VerdictDeny,
			Reason:   fmt.Sprintf("sir: mister-core binary integrity check failed: %v — run 'sir verify' or re-run install.sh", err),
		}, nil
	}

	payload, err := encodeMSTR1(req)
	if err != nil {
		return nil, fmt.Errorf("encode MSTR/1: %w", err)
	}

	cmd := exec.Command(path)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mister-core error: %v\n%s\n", err, stderr.String())
		return &Response{
			Decision: policy.VerdictDeny,
			Reason:   "sir: security engine unavailable — blocking for safety. Run `sir doctor` to investigate.",
		}, nil
	}

	resp, err := decodeMSTR1Response(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("decode MSTR/1 response: %w", err)
	}
	return resp, nil
}
