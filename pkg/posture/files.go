package posture

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
)

// ExtractManagedSubtree parses a JSON settings file and returns the
// canonicalized JSON bytes of the configured managed subtree.
func ExtractManagedSubtree(raw []byte, managedKey string) ([]byte, error) {
	if managedKey == "" {
		var canon interface{}
		if err := json.Unmarshal(raw, &canon); err != nil {
			return nil, err
		}
		return json.Marshal(canon)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	hooks, ok := obj[managedKey]
	if !ok {
		return []byte("null"), nil
	}
	var canon interface{}
	if err := json.Unmarshal(hooks, &canon); err != nil {
		return nil, err
	}
	return json.Marshal(canon)
}

// ExtractHooksSubtree is the legacy hooks-key wrapper retained for tests and
// older callers.
func ExtractHooksSubtree(raw []byte) ([]byte, error) {
	return ExtractManagedSubtree(raw, "hooks")
}

// AgentHookFile describes one host agent's hook config file and the matching
// canonical backup sir maintains at ~/.sir/.
type AgentHookFile struct {
	RelativePath  string
	DisplayPath   string
	AbsPath       string
	CanonicalPath string
	AgentID       string
	AgentName     string
	SubtreeKey    string
	SubtreeAtRoot bool
}

// NewAgentHookFile builds the runtime tamper metadata for one registered
// host agent from its typed config strategy.
func NewAgentHookFile(ag agent.Agent, homeDir string) AgentHookFile {
	spec := ag.GetSpec()
	return AgentHookFile{
		RelativePath:  spec.ConfigFile,
		DisplayPath:   "~/" + spec.ConfigFile,
		AbsPath:       filepath.Join(homeDir, spec.ConfigFile),
		CanonicalPath: spec.ConfigStrategy.CanonicalBackupPath(homeDir),
		AgentID:       string(ag.ID()),
		AgentName:     ag.Name(),
		SubtreeKey:    spec.ConfigStrategy.ManagedSubtreeKey,
		SubtreeAtRoot: spec.ConfigStrategy.ManagedSubtreeKey == "",
	}
}

func (f AgentHookFile) managedSubtreeKey() string {
	if f.SubtreeAtRoot {
		return ""
	}
	if f.SubtreeKey != "" {
		return f.SubtreeKey
	}
	return "hooks"
}

func knownAgentHookFiles() ([]AgentHookFile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	out := make([]AgentHookFile, 0, len(agent.All()))
	for _, ag := range agent.All() {
		out = append(out, NewAgentHookFile(ag, home))
	}
	return out, nil
}

// LookupAgentHookFileByRelativePath resolves a posture-file path like
// ".claude/settings.json" to the matching registered host-agent hook file.
func LookupAgentHookFileByRelativePath(relPath string) (AgentHookFile, bool) {
	files, err := knownAgentHookFiles()
	if err != nil {
		return AgentHookFile{}, false
	}
	for _, f := range files {
		if f.RelativePath == relPath {
			return f, true
		}
	}
	return AgentHookFile{}, false
}
