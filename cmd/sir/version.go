// sir version constant and update-check command.
//
// Update philosophy: sir does NOT auto-update, does NOT run a background
// checker, and does NOT have a self-update subcommand. The update path is
// external — re-run install.sh, or use a package manager. `sir version --check`
// is informational only: it queries the GitHub Releases API and prints whether
// a newer tag exists, along with release notes and checksums. It never
// downloads, never replaces, and always exits 0.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Version is the sir CLI version. Bumped per release in lockstep with the git tag.
// Embedded at build time via -ldflags="-X main.Version=vX.Y.Z" if needed; otherwise
// this constant is the source of truth.
const Version = "v0.0.2"

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

	release, err := fetchLatestRelease(latestReleaseURL, 5*time.Second)
	if err != nil || release.TagName == "" {
		fmt.Printf("sir %s (could not check for updates)\n", Version)
		return
	}

	if release.TagName == Version {
		fmt.Printf("sir %s (up to date)\n", Version)
		return
	}

	fmt.Printf("sir %s → %s available\n", Version, release.TagName)
	fmt.Println()

	// Release date
	if release.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, release.PublishedAt); err == nil {
			fmt.Printf("  released:  %s\n", t.Format("2006-01-02"))
		}
	}

	// Release URL
	if release.HTMLURL != "" {
		fmt.Printf("  details:   %s\n", release.HTMLURL)
	}
	fmt.Println()

	// Changelog (release body) — show first ~20 lines, trimmed
	if body := strings.TrimSpace(release.Body); body != "" {
		fmt.Println("  Changelog:")
		lines := strings.Split(body, "\n")
		limit := 20
		if len(lines) < limit {
			limit = len(lines)
		}
		for _, line := range lines[:limit] {
			fmt.Printf("    %s\n", line)
		}
		if len(lines) > limit {
			fmt.Printf("    ... (%d more lines — see details link above)\n", len(lines)-limit)
		}
		fmt.Println()
	}

	// Checksums — find checksums.txt in release assets
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			fmt.Printf("  checksums: %s\n", asset.DownloadURL)
			fmt.Println()
			break
		}
	}

	// Update instructions
	fmt.Println("  Update (pre-built binary):")
	fmt.Printf("    curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash -s -- %s\n", release.TagName)
	fmt.Println()
	fmt.Println("  Update (from source):")
	fmt.Printf("    cd sir && git fetch && git checkout %s && ./install.sh\n", release.TagName)
}

// releaseInfo holds the fields we care about from the GitHub Releases API.
type releaseInfo struct {
	TagName     string        `json:"tag_name"`
	PublishedAt string        `json:"published_at"`
	HTMLURL     string        `json:"html_url"`
	Body        string        `json:"body"`
	Assets      []releaseAsset `json:"assets"`
}

// releaseAsset holds a single release asset's metadata.
type releaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
}

// fetchLatestRelease queries the GitHub Releases API and returns the parsed
// release info. Returns a zero struct and error on any failure.
func fetchLatestRelease(url string, timeout time.Duration) (releaseInfo, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sir-version-check/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return releaseInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("github api status %d", resp.StatusCode)
	}

	var release releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return releaseInfo{}, err
	}
	return release, nil
}

// fetchLatestReleaseTag is the legacy helper used by tests. It delegates to
// fetchLatestRelease and returns just the tag name.
func fetchLatestReleaseTag(url string, timeout time.Duration) (string, error) {
	release, err := fetchLatestRelease(url, timeout)
	if err != nil {
		return "", err
	}
	return release.TagName, nil
}
