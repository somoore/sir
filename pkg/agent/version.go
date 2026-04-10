// Package agent — version detection and comparison helpers.
//
// DetectInstalledVersion runs `<binary> --version` with a short timeout
// and parses the output into a plain "major.minor.patch" string.
// SemverLessThan does a minimal semver comparison sufficient for
// MinVersion floors declared in AgentSpec.
//
// Both functions are fail-open by design: parse errors, missing
// binaries, timeouts, and unparseable output all return zero values.
// sir doctor consumes these to print advisory warnings, never to block.
package agent

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// versionRegexp extracts a bare major.minor.patch triple from arbitrary
// --version output (e.g. "codex 0.118.0", "gemini-cli/0.36.0",
// "Claude Code 1.2.3").
var versionRegexp = regexp.MustCompile(`\d+\.\d+\.\d+`)

// DetectInstalledVersion runs `<binary> --version` with a 2-second
// timeout and returns the first "major.minor.patch" triple found in
// the combined output. Returns "" on any failure (binary missing,
// --version flag absent, unparseable output, timeout).
func DetectInstalledVersion(binaryName string) string {
	if binaryName == "" {
		return ""
	}
	if _, err := exec.LookPath(binaryName); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryName, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	m := versionRegexp.FindString(string(out))
	return m
}

// SemverLessThan reports whether a < b using major.minor.patch
// comparison. Handles optional "v" prefix and "-prerelease" suffix
// (prereleases sort before their base version). Returns false on
// parse errors — fail-open: callers must not block on parse failure.
func SemverLessThan(a, b string) bool {
	aNums, aPre, aOK := parseSemver(a)
	bNums, bPre, bOK := parseSemver(b)
	if !aOK || !bOK {
		return false
	}
	// Pad to equal length so "1.2" vs "1.2.3" compares cleanly.
	for len(aNums) < len(bNums) {
		aNums = append(aNums, 0)
	}
	for len(bNums) < len(aNums) {
		bNums = append(bNums, 0)
	}
	for i := range aNums {
		if aNums[i] != bNums[i] {
			return aNums[i] < bNums[i]
		}
	}
	// All numeric parts equal — prerelease sorts before the base.
	if aPre == "" && bPre == "" {
		return false
	}
	if aPre != "" && bPre == "" {
		return true
	}
	if aPre == "" && bPre != "" {
		return false
	}
	return aPre < bPre
}

// parseSemver strips a leading "v" and an optional "-prerelease"
// suffix, then splits on "." and atoi's each part. Returns the
// numeric parts, the prerelease tag, and an ok flag.
func parseSemver(s string) ([]int, string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	pre := ""
	if idx := strings.Index(s, "-"); idx != -1 {
		pre = s[idx+1:]
		s = s[:idx]
	}
	if s == "" {
		return nil, "", false
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, "", false
		}
		nums = append(nums, n)
	}
	return nums, pre, true
}
