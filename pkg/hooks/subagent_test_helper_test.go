package hooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func runSubagentStartForTest(t *testing.T, projectRoot string, payload SubagentPayload) ([]byte, error) {
	t.Helper()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe in: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe out: %v", err)
	}
	os.Stdin = inR
	os.Stdout = outW

	if _, err := inW.Write(payloadJSON); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	inW.Close()

	readDone := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, outR); err != nil {
			readErr <- err
			return
		}
		readDone <- buf.Bytes()
	}()

	evalDone := make(chan error, 1)
	go func() {
		evalDone <- EvaluateSubagentStart(projectRoot, &agent.ClaudeAgent{})
		outW.Close()
	}()

	if err := <-evalDone; err != nil {
		return nil, err
	}
	select {
	case data := <-readDone:
		return data, nil
	case err := <-readErr:
		return nil, fmt.Errorf("read stdout: %w", err)
	}
}
