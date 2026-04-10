package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ApprovedServerNames returns the deduplicated server names in an inventory.
func ApprovedServerNames(servers []ServerInventory) []string {
	seen := make(map[string]bool)
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		name := strings.TrimSpace(server.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// PlanProxyRewrites filters the inventory to raw command-based servers that
// sir can rewrite through mcp-proxy.
func PlanProxyRewrites(servers []ServerInventory) []ServerInventory {
	var out []ServerInventory
	for _, server := range servers {
		if !server.HasCommand || server.Proxy.Wrapped || server.Proxy.Malformed {
			continue
		}
		out = append(out, server)
	}
	return out
}

// RewriteDiscoveredServers rewrites raw command-based MCP servers through sir
// mcp-proxy.
func RewriteDiscoveredServers(servers []ServerInventory, sirPath string) ([]RewriteResult, error) {
	planned := PlanProxyRewrites(servers)
	if len(planned) == 0 {
		return nil, nil
	}
	byPath := make(map[string][]string)
	for _, server := range planned {
		byPath[server.SourcePath] = append(byPath[server.SourcePath], server.Name)
	}

	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	results := make([]RewriteResult, 0, len(paths))
	for _, path := range paths {
		doc, err := ReadJSONFileMap(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		mcpServers, _ := doc["mcpServers"].(map[string]interface{})
		rewritten := make([]string, 0, len(byPath[path]))
		for _, serverName := range byPath[path] {
			entry, _ := mcpServers[serverName].(map[string]interface{})
			if entry == nil {
				continue
			}
			command, _ := entry["command"].(string)
			args, ok := InterfaceSliceToStrings(entry["args"])
			if !ok || command == "" {
				continue
			}
			if ClassifyProxy(command, args).Wrapped {
				continue
			}
			entry["command"] = sirPath
			entry["args"] = append([]string{"mcp-proxy", command}, args...)
			rewritten = append(rewritten, serverName)
		}
		if len(rewritten) == 0 {
			continue
		}
		if err := WriteJSONFileMap(path, doc); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		sort.Strings(rewritten)
		results = append(results, RewriteResult{Path: path, Servers: rewritten})
	}
	return results, nil
}

// ReadJSONFileMap reads a JSON config file into a generic map.
func ReadJSONFileMap(path string) (map[string]interface{}, error) {
	doc := make(map[string]interface{})
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// WriteJSONFileMap writes a generic JSON map with stable indentation.
func WriteJSONFileMap(path string, doc map[string]interface{}) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
