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

func writePermissionRequestResponse(w io.Writer, resp *HookResponse, ag agent.Agent) error {
	data, err := ag.FormatLifecycleResponse("PermissionRequest", string(resp.Decision), resp.Reason, "")
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return writeResponse(w, resp, ag)
	}
	_, err = w.Write(data)
	return err
}

type leaseLoadMetadata struct {
	previousHash   string
	currentHash    string
	refreshedBySir bool
}

func loadLease(projectRoot string) (*lease.Lease, error) {
	l, _, err := loadLeaseWithMetadata(projectRoot)
	return l, err
}

func loadLeaseWithMetadata(projectRoot string) (*lease.Lease, leaseLoadMetadata, error) {
	meta := leaseLoadMetadata{}
	if policy, err := session.LoadManagedPolicy(); err != nil {
		return nil, meta, fmt.Errorf("load managed policy: %w", err)
	} else if policy != nil {
		cloned, err := policy.CloneLease()
		if err != nil {
			return nil, meta, fmt.Errorf("clone managed policy lease: %w", err)
		}
		return cloned, meta, nil
	}
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	if priorHash, err := hashLeaseFile(projectRoot); err == nil {
		meta.previousHash = priorHash
	}
	l, err := lease.Load(leasePath)
	leaseExists := err == nil
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, meta, fmt.Errorf("load lease (%s): %w", leasePath, err)
		}
		l = lease.DefaultLease()
	}
	if autoApproveDiscoveredMCPServers(projectRoot, l, leasePath, leaseExists) {
		if currentHash, err := hashLeaseFile(projectRoot); err == nil {
			meta.currentHash = currentHash
			meta.refreshedBySir = meta.previousHash != "" && meta.currentHash != "" && meta.currentHash != meta.previousHash
		}
	}
	return l, meta, nil
}

func loadOrCreateSession(projectRoot string, l *lease.Lease, meta leaseLoadMetadata) (*session.State, error) {
	state, err := session.Load(projectRoot)
	if err == nil {
		if err := syncSessionLeaseHashAfterSirRefresh(state, meta); err != nil {
			return nil, fmt.Errorf("sync refreshed lease hash into session: %w", err)
		}
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
func autoApproveDiscoveredMCPServers(projectRoot string, l *lease.Lease, leasePath string, leaseExists bool) bool {
	discovered := mcp.DiscoverServerNames(projectRoot)
	if len(discovered) == 0 {
		return false
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
		return false
	}

	sort.Strings(merged)
	l.ApprovedMCPServers = merged
	if !leaseExists {
		return false
	}
	if err := l.Save(leasePath); err != nil {
		fmt.Fprintf(os.Stderr, "sir: warning: could not refresh approved_mcp_servers: %v\n", err)
		return false
	}
	return true
}

func syncSessionLeaseHashAfterSirRefresh(state *session.State, meta leaseLoadMetadata) error {
	if !meta.refreshedBySir || state == nil {
		return nil
	}
	if state.LeaseHash == "" || state.LeaseHash != meta.previousHash || meta.currentHash == "" {
		return nil
	}
	state.LeaseHash = meta.currentHash
	return state.Save()
}
