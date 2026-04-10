package session

import (
	"errors"
	"os"
	"sync"
	"testing"
)

// --- Update helper ----------------------------------------------------
//
// Update is the blessed Load→Mutate→Save helper introduced so hot
// code paths (sir allow-host, sir trust, sir unlock, sir doctor, the
// elicitation hook) cannot accidentally skip the file lock. These
// tests pin the contract: the mutation runs under the lock, the
// written state contains the mutation, fail-closed on corruption,
// fresh-session init on missing file, and concurrent Update calls
// serialise without losing writes.

func TestUpdate_AppliesMutationAndPersists(t *testing.T) {
	projectRoot := withTempProject(t)

	// Initial save so Update has a real session to load.
	initial := NewState(projectRoot)
	initial.SecretSession = false
	if err := initial.Save(); err != nil {
		t.Fatalf("save initial: %v", err)
	}

	if err := Update(projectRoot, func(st *State) error {
		st.SecretSession = true
		st.DenyAll = true
		st.DenyAllReason = "test"
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !loaded.SecretSession {
		t.Error("SecretSession mutation did not persist")
	}
	if !loaded.DenyAll {
		t.Error("DenyAll mutation did not persist")
	}
	if loaded.DenyAllReason != "test" {
		t.Errorf("DenyAllReason = %q, want 'test'", loaded.DenyAllReason)
	}
}

func TestUpdate_MissingFileCreatesFreshState(t *testing.T) {
	projectRoot := withTempProject(t)

	// No prior save — the state file does not exist.
	if _, err := os.Stat(StatePath(projectRoot)); !os.IsNotExist(err) {
		t.Fatalf("precondition: state file should not exist")
	}

	called := false
	if err := Update(projectRoot, func(st *State) error {
		called = true
		if st.ProjectRoot != projectRoot {
			t.Errorf("fresh state ProjectRoot = %q, want %q", st.ProjectRoot, projectRoot)
		}
		if st.SecretSession {
			t.Error("fresh state should not carry secret flag")
		}
		st.MarkSecretSessionWithScope("turn")
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !called {
		t.Fatal("mutator was not called")
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !loaded.SecretSession {
		t.Error("mutation on fresh state did not persist")
	}
}

func TestUpdate_FailsClosedOnCorruption(t *testing.T) {
	projectRoot := withTempProject(t)

	// Write corrupt session.json bytes directly (bypassing Save).
	if err := os.MkdirAll(StateDir(projectRoot), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(StatePath(projectRoot), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	called := false
	err := Update(projectRoot, func(st *State) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Update on corrupt session should have failed closed, got nil")
	}
	if called {
		t.Error("mutator should NOT be called when load fails")
	}
}

func TestUpdate_MutatorErrorPropagatesAndAborts(t *testing.T) {
	projectRoot := withTempProject(t)
	initial := NewState(projectRoot)
	if err := initial.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	sentinel := errors.New("mutator refused")
	err := Update(projectRoot, func(st *State) error {
		st.SecretSession = true // would persist if Update saves regardless
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}

	// The mutation must NOT have been saved — the mutator returned
	// an error, so the save is aborted.
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.SecretSession {
		t.Error("mutation persisted despite mutator error — Update should abort the save")
	}
}

func TestUpdate_ConcurrentCallsSerialiseAndPreserveWrites(t *testing.T) {
	projectRoot := withTempProject(t)
	initial := NewState(projectRoot)
	if err := initial.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := Update(projectRoot, func(st *State) error {
				st.IncrementTurn()
				return nil
			}); err != nil {
				t.Errorf("concurrent Update: %v", err)
			}
		}()
	}
	wg.Wait()

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	// Every Update that returned nil must have incremented Turn. If
	// the flock were broken, concurrent Load→mutate→Save sequences
	// would lose writes and the final counter would be < goroutines.
	if loaded.TurnCounter != goroutines {
		t.Errorf("Turn = %d, want %d — writes were lost under concurrent Update", loaded.TurnCounter, goroutines)
	}
}
