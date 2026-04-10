// Package tests contains concurrency and race-condition coverage for sir's
// session state and ledger packages. These tests lock in the invariants that
// keep concurrent tool calls (which Claude Code can fire in parallel) safe:
//
//   - Ledger: a file-level flock in withLedgerLock serializes Append calls.
//     Hash-chain integrity, index monotonicity, and per-line JSON validity
//     must hold under concurrent appends and concurrent Verify/ReadAll.
//
//   - Session (file I/O): Save serializes its critical section with the
//     State mutex, marshals under the lock, and persists via temp-file +
//     atomic rename. Concurrent Save calls produce a valid JSON file and
//     concurrent Load calls never observe a partial write.
//
//   - Session (in-memory): the State struct guards every exported mutator
//     and reader with sync.RWMutex. Concurrent MarkSecretSession,
//     IncrementTurn, and field reads must be race-free under -race.
//
// Run with: go test -race -v -count=1 ./tests/ -run Concurrency
package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// setupTempProject creates a temporary directory that mimics a project root
// and pre-creates the sir state directory so session.StateDir resolves.
func setupTempProject(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	stateDir := session.StateDir(tmpDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("failed to create state dir: %v", err)
	}
	return tmpDir
}

// ---------------------------------------------------------------------------
// Session concurrency tests — file I/O
// ---------------------------------------------------------------------------

// TestConcurrency_Session_ConcurrentSave verifies that concurrent Save calls
// produce a valid JSON file. Save uses temp-file + rename, so the final file
// is always one writer's complete payload (last writer wins).
func TestConcurrency_Session_ConcurrentSave(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s := session.NewState(projectRoot)
			s.TurnCounter = id
			if err := s.Save(); err != nil {
				errs <- fmt.Errorf("goroutine %d save: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// The file must be valid JSON after all saves complete.
	data, err := os.ReadFile(session.StatePath(projectRoot))
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var s session.State
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("session file is corrupt after concurrent saves: %v", err)
	}
}

// TestConcurrency_Session_LoadDuringSave runs Load calls concurrently with
// Save calls and asserts that the atomic-rename strategy in Save prevents
// Load from ever observing a partially-written JSON payload. Any unmarshal
// error is logged so regressions in the temp-file/rename pipeline surface
// loudly even though they would not, on their own, fail the test.
func TestConcurrency_Session_LoadDuringSave(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	// Seed an initial state.
	initial := session.NewState(projectRoot)
	if err := initial.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const goroutines = 30
	var wg sync.WaitGroup
	var corruptReads atomic.Int64
	var totalReads atomic.Int64
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(id int) {
				defer wg.Done()
				s := session.NewState(projectRoot)
				s.TurnCounter = id
				if err := s.Save(); err != nil {
					errs <- fmt.Errorf("save goroutine %d: %w", id, err)
				}
			}(i)
		} else {
			go func(_ int) {
				defer wg.Done()
				totalReads.Add(1)
				_, err := session.Load(projectRoot)
				if err != nil {
					// Atomic rename means Load should never observe a
					// partial write. Count any unmarshal errors so a
					// regression in Save surfaces in the test log.
					corruptReads.Add(1)
				}
			}(i)
		}
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	corrupt := corruptReads.Load()
	total := totalReads.Load()
	if corrupt > 0 {
		t.Errorf("%d/%d Load calls observed a partial write — atomic rename in Save is broken", corrupt, total)
	} else {
		t.Logf("Load saw consistent JSON across all %d reads", total)
	}

	// Final state must be valid (no concurrent access at this point).
	loaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("final load failed (file corrupt even after all writes settled): %v", err)
	}
	if loaded.ProjectRoot != projectRoot {
		t.Errorf("final state has wrong project root")
	}
}

// TestConcurrency_Session_DataIntegrity verifies that concurrent saves with
// different PostureHashes do not produce a file with mixed/invalid data.
func TestConcurrency_Session_DataIntegrity(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	initial := session.NewState(projectRoot)
	initial.PostureHashes["hooks.json"] = "abc123"
	if err := initial.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const rounds = 20
	var wg sync.WaitGroup
	var corruptReads atomic.Int64

	for i := 0; i < rounds; i++ {
		wg.Add(2)

		go func(id int) {
			defer wg.Done()
			s := session.NewState(projectRoot)
			s.PostureHashes = map[string]string{
				"hooks.json": fmt.Sprintf("hash-%d", id),
			}
			_ = s.Save()
		}(i)

		go func(_ int) {
			defer wg.Done()
			loaded, err := session.Load(projectRoot)
			if err != nil {
				corruptReads.Add(1)
				return
			}
			if loaded.PostureHashes == nil {
				corruptReads.Add(1)
			}
		}(i)
	}

	wg.Wait()

	corrupt := corruptReads.Load()
	t.Logf("Session data integrity: %d/%d reads returned corrupt/nil data", corrupt, rounds)

	// Final state must be valid.
	loaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("final load failed: %v", err)
	}
	if loaded.PostureHashes == nil {
		t.Error("final PostureHashes is nil")
	}
}

// ---------------------------------------------------------------------------
// Session concurrency tests — in-memory race detection
// These tests are most useful with -race flag. Without it, races may not
// manifest as visible failures, but the race detector will catch them.
// ---------------------------------------------------------------------------

// TestConcurrency_Session_MarkSecretRace exercises concurrent MarkSecretSession
// and SecretSession reads. With -race, this proves the State struct needs a mutex.
func TestConcurrency_Session_MarkSecretRace(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)
	s := session.NewState(projectRoot)

	const goroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				s.MarkSecretSession()
			}()
		} else {
			go func() {
				defer wg.Done()
				_ = s.Snapshot().SecretSession // race-free read
			}()
		}
	}

	wg.Wait()

	// After all goroutines complete, secret must be set.
	if !s.Snapshot().SecretSession {
		t.Error("SecretSession should be true after concurrent MarkSecretSession calls")
	}
}

// TestConcurrency_Session_IncrementTurnRace exercises concurrent IncrementTurn
// and TurnCounter reads. With -race, this detects unsynchronized field access.
func TestConcurrency_Session_IncrementTurnRace(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)
	s := session.NewState(projectRoot)

	const goroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				s.IncrementTurn()
			}()
		} else {
			go func() {
				defer wg.Done()
				_ = s.Snapshot().TurnCounter // race-free read
			}()
		}
	}

	wg.Wait()

	if s.Snapshot().TurnCounter < 1 {
		t.Error("TurnCounter should be >= 1 after concurrent increments")
	}
}

// TestConcurrency_Session_TurnScopedSecretClearance tests that turn-scoped
// secrets are cleared when the turn counter advances past the approval turn
// under concurrent IncrementTurn calls.
func TestConcurrency_Session_TurnScopedSecretClearance(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)
	s := session.NewState(projectRoot)
	s.MarkSecretSessionWithScope("turn")

	const goroutines = 20
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.IncrementTurn()
		}()
	}

	wg.Wait()

	// With turn-scoped approval and turns advanced, secret should be cleared.
	// Snapshot() ensures all four fields are read under one read-lock for a
	// self-consistent view.
	snap := s.Snapshot()
	if snap.SecretSession && snap.ApprovalScope == "turn" && snap.TurnCounter > snap.SecretApprovalTurn {
		t.Error("turn-scoped secret should have been cleared after turn advanced")
	}
}

// ---------------------------------------------------------------------------
// Ledger concurrency tests
// ---------------------------------------------------------------------------

func makeEntry(toolName, verb, target, decision string) *ledger.Entry {
	return &ledger.Entry{
		ToolName: toolName,
		Verb:     verb,
		Target:   target,
		Decision: decision,
		Reason:   "test",
	}
}

// TestConcurrency_Ledger_ConcurrentAppend verifies that all entries are
// written when multiple goroutines append simultaneously. The file lock
// in withLedgerLock should serialize these correctly.
func TestConcurrency_Ledger_ConcurrentAppend(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e := makeEntry("Bash", "execute_dry_run", fmt.Sprintf("cmd-%d", id), "allow")
			if err := ledger.Append(projectRoot, e); err != nil {
				errs <- fmt.Errorf("append goroutine %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, len(entries))
	}
}

// TestConcurrency_Ledger_HashChainIntegrity verifies the hash chain remains
// intact after concurrent appends. This is the critical correctness property.
func TestConcurrency_Ledger_HashChainIntegrity(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 25
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e := makeEntry("Read", "read_ref", fmt.Sprintf("file-%d.go", id), "allow")
			if err := ledger.Append(projectRoot, e); err != nil {
				errs <- fmt.Errorf("append %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	verified, err := ledger.Verify(projectRoot)
	if err != nil {
		t.Fatalf("hash chain broken after concurrent appends: %v", err)
	}
	if verified != goroutines {
		t.Errorf("verified %d entries, expected %d", verified, goroutines)
	}
}

// TestConcurrency_Ledger_ReadWhileWrite verifies that ReadAll returns
// consistent data even when appends are in progress.
func TestConcurrency_Ledger_ReadWhileWrite(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	// Seed entries so reads see data.
	for i := 0; i < 5; i++ {
		e := makeEntry("Bash", "execute_dry_run", fmt.Sprintf("seed-%d", i), "allow")
		if err := ledger.Append(projectRoot, e); err != nil {
			t.Fatalf("seed append %d: %v", i, err)
		}
	}

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(id int) {
				defer wg.Done()
				e := makeEntry("Write", "stage_write", fmt.Sprintf("concurrent-%d", id), "allow")
				if err := ledger.Append(projectRoot, e); err != nil {
					errs <- fmt.Errorf("append %d: %w", id, err)
				}
			}(i)
		} else {
			go func(id int) {
				defer wg.Done()
				entries, err := ledger.ReadAll(projectRoot)
				if err != nil {
					errs <- fmt.Errorf("read %d: %w", id, err)
					return
				}
				if len(entries) < 5 {
					errs <- fmt.Errorf("read %d: expected >= 5 entries, got %d", id, len(entries))
				}
			}(i)
		}
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Final verify: hash chain must be intact.
	verified, err := ledger.Verify(projectRoot)
	if err != nil {
		t.Fatalf("hash chain broken after concurrent read/write: %v", err)
	}
	expectedMin := 5 + goroutines/2
	if verified < expectedMin {
		t.Errorf("expected at least %d verified entries, got %d", expectedMin, verified)
	}
}

// TestConcurrency_Ledger_IndexMonotonicity verifies that indices are strictly
// sequential (0, 1, 2, ...) and PrevHash chains correctly after concurrent appends.
func TestConcurrency_Ledger_IndexMonotonicity(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 40
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e := makeEntry("Bash", "net_external", fmt.Sprintf("host-%d", id), "deny")
			if err := ledger.Append(projectRoot, e); err != nil {
				errs <- fmt.Errorf("append %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	for i, e := range entries {
		if e.Index != i {
			t.Errorf("entry %d has index %d (expected %d)", i, e.Index, i)
		}
		if i == 0 {
			if e.PrevHash != genesis {
				t.Errorf("entry 0 has PrevHash %q, expected genesis", e.PrevHash)
			}
		} else {
			if e.PrevHash != entries[i-1].EntryHash {
				t.Errorf("entry %d PrevHash mismatch: got %q, expected %q",
					i, e.PrevHash, entries[i-1].EntryHash)
			}
		}
	}
}

// TestConcurrency_Ledger_NoDuplicateIndices verifies no two entries share
// the same index after concurrent appends.
func TestConcurrency_Ledger_NoDuplicateIndices(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e := makeEntry("Read", "read_ref", fmt.Sprintf("target-%d", id), "allow")
			if err := ledger.Append(projectRoot, e); err != nil {
				errs <- fmt.Errorf("append %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	seen := make(map[int]bool)
	for _, e := range entries {
		if seen[e.Index] {
			t.Errorf("duplicate index %d found", e.Index)
		}
		seen[e.Index] = true
	}
}

// TestConcurrency_Ledger_VerifyDuringAppend runs concurrent Verify calls
// alongside appends to ensure Verify never sees a broken chain mid-flight.
func TestConcurrency_Ledger_VerifyDuringAppend(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	// Seed entries.
	for i := 0; i < 10; i++ {
		e := makeEntry("Bash", "execute_dry_run", fmt.Sprintf("seed-%d", i), "allow")
		if err := ledger.Append(projectRoot, e); err != nil {
			t.Fatalf("seed append %d: %v", i, err)
		}
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%3 == 0 {
			go func(id int) {
				defer wg.Done()
				e := makeEntry("Write", "stage_write", fmt.Sprintf("file-%d", id), "allow")
				if err := ledger.Append(projectRoot, e); err != nil {
					errs <- fmt.Errorf("append %d: %w", id, err)
				}
			}(i)
		} else {
			go func(id int) {
				defer wg.Done()
				n, err := ledger.Verify(projectRoot)
				if err != nil {
					errs <- fmt.Errorf("verify %d: %w", id, err)
					return
				}
				if n < 10 {
					errs <- fmt.Errorf("verify %d: only %d entries (expected >= 10)", id, n)
				}
			}(i)
		}
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestConcurrency_Ledger_FileNotCorrupted does a stress test with 50 concurrent
// appends and verifies every line in the resulting file is valid JSON.
func TestConcurrency_Ledger_FileNotCorrupted(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e := makeEntry("Bash", "execute_dry_run", fmt.Sprintf("stress-%d", id), "allow")
			if err := ledger.Append(projectRoot, e); err != nil {
				errs <- fmt.Errorf("append %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	ledgerPath := filepath.Join(session.StateDir(projectRoot), "ledger.jsonl")
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger file: %v", err)
	}

	lines := 0
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		lines++
		var e ledger.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Errorf("corrupt JSON line %d: %v\nline: %s", lines, err, string(line))
		}
	}

	if lines != goroutines {
		t.Errorf("expected %d JSON lines, got %d", goroutines, lines)
	}
}

// ---------------------------------------------------------------------------
// Combined session + ledger concurrency
// ---------------------------------------------------------------------------

// TestConcurrency_Combined_SessionAndLedger exercises both session saves
// and ledger appends concurrently to the same project state directory.
// Both ledger entries and the final session.json must be intact.
func TestConcurrency_Combined_SessionAndLedger(t *testing.T) {
	t.Parallel()
	projectRoot := setupTempProject(t)

	s := session.NewState(projectRoot)
	if err := s.Save(); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	const goroutines = 30
	var wg sync.WaitGroup
	var sessionErrs atomic.Int64
	ledgerErrs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			go func(id int) {
				defer wg.Done()
				st := session.NewState(projectRoot)
				st.TurnCounter = id
				st.MarkSecretSession()
				if err := st.Save(); err != nil {
					sessionErrs.Add(1)
				}
			}(i)
		} else {
			go func(id int) {
				defer wg.Done()
				e := makeEntry("Read", "read_ref", fmt.Sprintf(".env-%d", id), "ask")
				e.Sensitivity = "secret"
				if err := ledger.Append(projectRoot, e); err != nil {
					ledgerErrs <- fmt.Errorf("ledger append %d: %w", id, err)
				}
			}(i)
		}
	}

	wg.Wait()
	close(ledgerErrs)

	for err := range ledgerErrs {
		t.Error(err)
	}

	// Ledger MUST verify (it has proper file locking).
	verified, err := ledger.Verify(projectRoot)
	if err != nil {
		t.Fatalf("ledger verify: %v", err)
	}
	expectedEntries := goroutines / 2
	if verified != expectedEntries {
		t.Errorf("expected %d ledger entries, got %d", expectedEntries, verified)
	}

	// Session file should be valid after all writes settle.
	loaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("final session load failed (file corrupt after all writes settled): %v", err)
	}
	if loaded.ProjectRoot != projectRoot {
		t.Errorf("session project root mismatch")
	}

	sessErrs := sessionErrs.Load()
	if sessErrs > 0 {
		t.Logf("NOTE: %d session save errors during concurrent access", sessErrs)
	}
}

// splitLines splits data by newline without producing empty trailing elements.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
