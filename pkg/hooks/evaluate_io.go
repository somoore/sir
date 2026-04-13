package hooks

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/mcp"
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
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	l, err := lease.Load(leasePath)
	leaseExists := err == nil
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("load lease (%s): %w", leasePath, err)
		}
		l = lease.DefaultLease()
	}
	autoApproveDiscoveredMCPServers(projectRoot, l, leasePath, leaseExists)
	return l, nil
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

// autoApproveDiscoveredMCPServers keeps approved_mcp_servers aligned with the
// MCP servers currently configured in the user's project/global config. sir
// already seeds this list during install; refreshing it here prevents the
// lease from going stale when .mcp.json or agent settings change later.
//
// Managed mode skips this entirely because the manifest lease is the trust
// anchor and local discovery must not widen it.
func autoApproveDiscoveredMCPServers(projectRoot string, l *lease.Lease, leasePath string, leaseExists bool) {
	discovered := mcp.DiscoverServerNames(projectRoot)
	if len(discovered) == 0 {
		return
	}

	approved := make(map[string]struct{}, len(l.ApprovedMCPServers)+len(discovered))
	merged := make([]string, 0, len(l.ApprovedMCPServers)+len(discovered))
	for _, name := range l.ApprovedMCPServers {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := approved[name]; ok {
			continue
		}
		approved[name] = struct{}{}
		merged = append(merged, name)
	}

	changed := false
	for _, name := range discovered {
		if _, ok := approved[name]; ok {
			continue
		}
		approved[name] = struct{}{}
		merged = append(merged, name)
		changed = true
	}
	if !changed {
		return
	}

	sort.Strings(merged)
	l.ApprovedMCPServers = merged
	if !leaseExists {
		return
	}
	if err := l.Save(leasePath); err != nil {
		fmt.Fprintf(os.Stderr, "sir: warning: could not refresh approved_mcp_servers: %v\n", err)
	}
}
