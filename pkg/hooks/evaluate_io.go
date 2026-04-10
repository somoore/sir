package hooks

import (
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

const maxPayloadBytes = 10 * 1024 * 1024 // 10 MB

func readPayload(r io.Reader, ag agent.Agent) (*HookPayload, error) {
	limited := io.LimitReader(r, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	return ag.ParsePreToolUse(data)
}

func writeResponse(w io.Writer, resp *HookResponse, ag agent.Agent) error {
	data, err := ag.FormatPreToolUseResponse(string(resp.Decision), resp.Reason)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func loadLease(projectRoot string) (*lease.Lease, error) {
	if policy, err := session.LoadManagedPolicy(); err != nil {
		return nil, fmt.Errorf("load managed policy: %w", err)
	} else if policy != nil {
		return policy.CloneLease()
	}
	leasePath := session.StateDir(projectRoot) + "/lease.json"
	l, err := lease.Load(leasePath)
	if err == nil {
		return l, nil
	}
	if os.IsNotExist(err) {
		return lease.DefaultLease(), nil
	}
	return nil, fmt.Errorf("load lease (%s): %w", leasePath, err)
}

func loadOrCreateSession(projectRoot string, l *lease.Lease) (*session.State, error) {
	state, err := session.Load(projectRoot)
	if err == nil {
		return state, nil
	}
	if os.IsNotExist(err) {
		return SessionStart(projectRoot, l)
	}
	return nil, fmt.Errorf("load session: %w", err)
}

func isToolMCP(toolName string) bool {
	return len(toolName) > 5 && toolName[:5] == "mcp__"
}
