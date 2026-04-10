// sir version constant and update-check command.
//
// Update philosophy: sir does NOT auto-update, does NOT run a background
// checker, and does NOT have a self-update subcommand. The update path is
// external — re-run install.sh, or use a package manager. `sir version --check`
// is informational only: it queries the GitHub Releases API and prints whether
// a newer tag exists. It never downloads, never replaces, and always exits 0.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Version is the sir CLI version. Bumped per release in lockstep with the git tag.
// Embedded at build time via -ldflags="-X main.Version=vX.Y.Z" if needed; otherwise
// this constant is the source of truth.
const Version = "v0.1.1"

// latestReleaseURL is the GitHub Releases API endpoint queried by `sir version --check`.
// No authentication is sent. The request is a single GET with a 5-second timeout.
const latestReleaseURL = "https://api.github.com/repos/somoore/sir/releases/latest"

// cmdVersion handles `sir version` and `sir version --check`.
//
// Without flags: prints the local version.
// With --check: also queries GitHub for the latest release tag and compares.
//
// Network failures are non-fatal: any error prints "could not check for updates"
// and the command still exits 0. This is informational, not enforcement.
func cmdVersion(args []string) {
	check := false
	for _, a := range args {
		if a == "--check" {
			check = true
		}
	}

	if !check {
		fmt.Printf("sir %s\n", Version)
		return
	}

	latest, err := fetchLatestReleaseTag(latestReleaseURL, 5*time.Second)
	if err != nil || latest == "" {
		fmt.Printf("sir %s (could not check for updates)\n", Version)
		return
	}

	if latest == Version {
		fmt.Printf("sir %s (up to date)\n", Version)
		return
	}
	fmt.Printf("sir %s (latest: %s — re-run install.sh to update)\n", Version, latest)
}

// fetchLatestReleaseTag queries the GitHub Releases API and extracts the
// `tag_name` field from the JSON response. Returns ("", err) on any failure.
// Uses a bounded http.Client with the supplied timeout — no retries, no
// keep-alives, no follow-up requests.
func fetchLatestReleaseTag(url string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sir-version-check/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api status %d", resp.StatusCode)
	}

	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.TagName, nil
}
