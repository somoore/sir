package ledger

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyedChainRejectsRecomputeWithoutKey(t *testing.T) {
	projectRoot := setupTestProject(t)
	for i := 0; i < 3; i++ {
		if err := Append(projectRoot, &Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "git status",
			Decision: "allow",
			Reason:   "seed",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].HashVersion < 5 {
		t.Fatalf("new entry hash_version = %d, want keyed version >= 5", entries[0].HashVersion)
	}

	// Simulate an attacker who can rewrite ledger.jsonl but does not have
	// ~/.sir/ledger.key: they delete the middle entry and recompute the
	// chain with a different key. Verify must reject it.
	wrongKey := bytes.Repeat([]byte{0xAB}, 32)
	rewritten := []Entry{entries[0], entries[2]}
	prev := strings.Repeat("0", 64)
	for i := range rewritten {
		rewritten[i].Index = i
		rewritten[i].PrevHash = prev
		rewritten[i].HashVersion = currentHashVersion
		rewritten[i].EntryHash = computeHashV5(&rewritten[i], wrongKey)
		prev = rewritten[i].EntryHash
	}

	var buf bytes.Buffer
	for i := range rewritten {
		data, err := json.Marshal(rewritten[i])
		if err != nil {
			t.Fatalf("marshal rewritten entry: %v", err)
		}
		buf.Write(append(data, '\n'))
	}
	if err := os.WriteFile(LedgerPath(projectRoot), buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write rewritten ledger: %v", err)
	}

	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("Verify accepted a chain recomputed with an unknown key")
	}
}

func TestKeyedChainDetectsFieldTamper(t *testing.T) {
	projectRoot := setupTestProject(t)
	if err := Append(projectRoot, &Entry{
		ToolName: "Bash",
		Verb:     "execute_dry_run",
		Target:   "git status",
		Decision: "allow",
		Reason:   "original",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err := ReadAll(projectRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ReadAll = %v, %v", entries, err)
	}
	entries[0].Decision = "deny"
	data, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(LedgerPath(projectRoot), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("Verify accepted a tampered entry")
	}
}

func resetLedgerKeyCache(t *testing.T) {
	t.Helper()
	ledgerKeyMu.Lock()
	ledgerKeyCache = nil
	ledgerKeyMu.Unlock()
	t.Cleanup(func() {
		ledgerKeyMu.Lock()
		ledgerKeyCache = nil
		ledgerKeyMu.Unlock()
	})
}

func TestLedgerKeyCreationPublishesOnlyTheFinishedKey(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIR_STATE_HOME", state)
	resetLedgerKeyCache(t)

	key, err := ledgerKey()
	if err != nil {
		t.Fatalf("ledgerKey: %v", err)
	}
	dir := filepath.Join(state, ".sir")
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read key dir: %v", err)
	}
	if len(names) != 1 || names[0].Name() != "ledger.key" {
		t.Fatalf("key dir must hold only ledger.key, got %v", names)
	}
	info, err := os.Stat(filepath.Join(dir, "ledger.key"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(filepath.Join(dir, "ledger.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	onDisk, err := decodeLedgerKey(data)
	if err != nil || !bytes.Equal(onDisk, key) {
		t.Fatalf("on-disk key does not match returned key (err=%v)", err)
	}
}

func TestLedgerKeyNeverReplacesAnExistingKey(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIR_STATE_HOME", state)
	resetLedgerKeyCache(t)

	existing := bytes.Repeat([]byte{0x42}, 32)
	dir := filepath.Join(state, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ledger.key"), []byte(hex.EncodeToString(existing)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ledgerKey()
	if err != nil {
		t.Fatalf("ledgerKey: %v", err)
	}
	if !bytes.Equal(key, existing) {
		t.Fatal("ledgerKey must return the existing key")
	}
}
