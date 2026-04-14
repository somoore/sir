package lifecycle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

// RebaselineSummary reports the outcome of RebaselineAllProjects.
type RebaselineSummary struct {
	Refreshed      int
	DenyAllCleared int
	Skipped        []RebaselineSkip
}

// RebaselineSkip records why one project state was left untouched. Exposed so
// callers (install, tests) can print or assert skip reasons.
type RebaselineSkip struct {
	Project string
	Reason  string
}

// hookInducedDenyPrefixes enumerates the deny_all reason strings produced by
// hook/posture tamper detectors that a legitimate `sir install` invalidates.
// Reasons outside this list (secret_session lock, session.json tamper,
// lease.json tamper, binary manifest mismatch, runtime-containment stale, etc.)
// are preserved — those denies were not caused by install rewriting hooks.
//
// Each entry must match the exact leading text of a reason string set via
// state.SetDenyAll somewhere in pkg/hooks. When adding a new tamper-based
// deny reason, add its prefix here if install is expected to clear it.
// Current set, traced from every non-test SetDenyAll call site:
//
//   - "posture file tampered: …"                   — post_evaluate_checks.go, session_end.go
//   - "posture tampered before delegation: …"      — subagent.go
//   - "managed hook baseline unavailable …"        — post_evaluate_checks.go, config_change.go
//     (covers both the plain form and the "during config change" variant)
//   - "global hooks file tampered: …"              — post_evaluate_checks.go
//   - "global hooks modified during config change: …" — config_change.go
var hookInducedDenyPrefixes = []string{
	"posture file tampered",
	"posture tampered before delegation",
	"managed hook baseline unavailable",
	"global hooks file tampered",
	"global hooks modified during config change",
}

// RebaselineAllProjects walks every per-project state directory under
// ~/.sir/projects/ and refreshes posture_hashes, global_hook_hash, and
// lease_hash against the current on-disk files. It also clears deny_all, but
// only when the recorded reason was induced by hook-file drift. Other denies
// (secret-session, runtime containment, etc.) are preserved.
//
// This is invoked by `sir install` after the global host-agent hook files have
// been rewritten. Install is user-initiated from a terminal, out-of-band of
// any agent session — so the hook changes during install are expected by
// definition. The tamper detector still catches in-session agent modifications
// against the new baseline on the next tool call.
//
// Errors reading the projects directory are returned to the caller. Per-project
// failures are recorded in Summary.Skipped so one bad state directory cannot
// abort the whole rebaseline pass.
func RebaselineAllProjects() (RebaselineSummary, error) {
	var summary RebaselineSummary
	home, err := os.UserHomeDir()
	if err != nil {
		return summary, fmt.Errorf("home dir: %w", err)
	}
	projectsDir := filepath.Join(home, ".sir", "projects")
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("read projects dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stateDir := filepath.Join(projectsDir, entry.Name())
		projectRoot, skipReason := projectRootFromState(stateDir)
		if skipReason != "" {
			summary.Skipped = append(summary.Skipped, RebaselineSkip{Project: entry.Name(), Reason: skipReason})
			continue
		}

		// Defend against a state directory whose session.json points to a
		// project_root that no longer hashes to this directory (copied/moved
		// state). Rebaselining via session.Update would write to a *different*
		// directory, leaving the stale dir behind.
		if session.ProjectHash(projectRoot) != entry.Name() {
			summary.Skipped = append(summary.Skipped, RebaselineSkip{
				Project: entry.Name(),
				Reason:  "project_root hash mismatch (state dir was copied or path renamed)",
			})
			continue
		}

		leasePath := filepath.Join(stateDir, "lease.json")
		l, leaseErr := lease.Load(leasePath)
		if leaseErr != nil {
			summary.Skipped = append(summary.Skipped, RebaselineSkip{
				Project: projectRoot,
				Reason:  fmt.Sprintf("lease load: %v", leaseErr),
			})
			continue
		}

		if err := rebaselineProject(projectRoot, l, &summary); err != nil {
			summary.Skipped = append(summary.Skipped, RebaselineSkip{
				Project: projectRoot,
				Reason:  err.Error(),
			})
			continue
		}
	}
	return summary, nil
}

func rebaselineProject(projectRoot string, l *lease.Lease, summary *RebaselineSummary) error {
	return session.Update(projectRoot, func(state *session.State) error {
		state.PostureHashes = posture.HashSentinelFiles(projectRoot, l.PostureFiles)
		if globalHash, err := posture.HashGlobalHooksFile(); err == nil {
			state.GlobalHookHash = globalHash
		}
		if leaseHash, err := posture.HashLeaseFile(projectRoot); err == nil {
			state.LeaseHash = leaseHash
		}
		if state.DenyAll && isHookInducedDenyReason(state.DenyAllReason) {
			state.DenyAll = false
			state.DenyAllReason = ""
			summary.DenyAllCleared++
		}
		summary.Refreshed++
		return nil
	})
}

func isHookInducedDenyReason(reason string) bool {
	trim := strings.TrimSpace(reason)
	if trim == "" {
		return false
	}
	for _, p := range hookInducedDenyPrefixes {
		if strings.HasPrefix(trim, p) {
			return true
		}
	}
	return false
}

// projectRootFromState reads only the project_root field out of session.json.
// We avoid session.Load here because it validates the full schema and would
// reject forward-incompatible entries we'd rather report as a skip than an
// error. The empty-string return paired with a non-empty reason lets callers
// distinguish "no session here" from "corrupt session".
func projectRootFromState(stateDir string) (string, string) {
	sessionPath := filepath.Join(stateDir, "session.json")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "no session.json"
		}
		return "", fmt.Sprintf("read session.json: %v", err)
	}
	var m struct {
		ProjectRoot string `json:"project_root"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Sprintf("parse session.json: %v", err)
	}
	if m.ProjectRoot == "" {
		return "", "empty project_root in session.json"
	}
	return m.ProjectRoot, ""
}
