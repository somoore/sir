// Package core implements the MSTR/1 protocol bridge to mister-core.
// It executes the mister-core binary and communicates via stdin/stdout.
package core

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/somoore/sir/pkg/policy"
)

// Evaluate sends a request to mister-core and returns the verdict.
// If mister-core is not available, it falls back to local policy evaluation.
func Evaluate(req *Request) (*Response, error) {
	path, err := exec.LookPath(CoreBinaryPath)
	if err != nil {
		return localEvaluate(req)
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
