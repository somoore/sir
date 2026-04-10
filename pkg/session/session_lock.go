package session

import (
	"fmt"
	"os"
	"syscall"
)

// WithSessionLock acquires an exclusive file lock on session.json.lock,
// calls fn, then releases the lock. This serialises concurrent Load/Save
// calls so the read→mutate→write pipeline is atomic at the process level.
func WithSessionLock(projectRoot string, fn func() error) error {
	dir := StateDir(projectRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lockPath := StatePath(projectRoot) + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open session lock: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire session lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// LoadLocked reads session state from disk while holding the session file lock.
// The returned unlock function MUST be called after Save to release the lock.
// This ensures the Load→Mutate→Save pipeline is atomic.
func LoadLocked(projectRoot string) (unlock func(), state *State, err error) {
	dir := StateDir(projectRoot)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return func() {}, nil, mkErr
	}
	lockPath := StatePath(projectRoot) + ".lock"
	lockFile, openErr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if openErr != nil {
		return func() {}, nil, fmt.Errorf("open session lock: %w", openErr)
	}
	if flockErr := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); flockErr != nil {
		lockFile.Close()
		return func() {}, nil, fmt.Errorf("acquire session lock: %w", flockErr)
	}
	releaseFn := func() {
		syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck
		lockFile.Close()
	}

	s, loadErr := Load(projectRoot)
	if loadErr != nil {
		releaseFn()
		return func() {}, nil, loadErr
	}
	return releaseFn, s, nil
}
