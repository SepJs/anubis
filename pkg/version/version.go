// Package version handles version metadata and GitHub release update checking.
// The Version var is intentionally a var (not const) so it can be stamped at
// build time via -ldflags, which is how it stays in sync with Git release tags:
//
//   go build -ldflags "-X github.com/SepJs/anubis/pkg/version.Version=$(git describe --tags --abbrev=0)"
//
// This way whatever tag you push to GitHub becomes the version string shown
// in --version and compared against the latest release API response.
package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Version is stamped at build time via ldflags. Default is "dev" so a plain
// `go build` without the flag is obviously identifiable as a local build.
var (
	Version   = "dev"
	BuildDate = "unknown"
	GitHash   = "unknown"
)

const (
	ProjectURL  = "https://github.com/SepJs/anubis"
	ReleasesAPI = "https://api.github.com/repos/SepJs/anubis/releases/latest"
	httpTimeout = 8 * time.Second
)

// ReleaseInfo mirrors the GitHub releases API response fields we use.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	PublishedAt string         `json:"published_at"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
}

// ReleaseAsset is a single downloadable binary attached to a release.
type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int    `json:"size"`
}

// Info returns a one-line human-readable version string.
func Info() string {
	return fmt.Sprintf("Anubis v%s (build %s, commit %s)", Version, BuildDate, GitHash)
}

// FetchLatest queries the GitHub releases API for the latest published release.
// Returns an error if offline, rate-limited, or no releases exist yet.
func FetchLatest() (*ReleaseInfo, error) {
	client := &http.Client{Timeout: httpTimeout}

	req, err := http.NewRequest(http.MethodGet, ReleasesAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("version: build request: %w", err)
	}
	// GitHub API requires a User-Agent header or it returns 403.
	req.Header.Set("User-Agent", "anubis-scanner/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("version: request failed (offline?): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("version: no releases found at %s", ProjectURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("version: GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("version: read response: %w", err)
	}

	var release ReleaseInfo
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("version: parse response: %w", err)
	}
	if release.TagName == "" {
		return nil, fmt.Errorf("version: empty tag_name in response")
	}

	return &release, nil
}

// IsNewer reports whether latestTag is a higher version than the currently
// running Version. Comparison is numeric per dot-segment so "1.10.0" > "1.9.0".
func IsNewer(latestTag string) bool {
	latest := stripV(latestTag)
	current := stripV(Version)

	lp, lok := parseVer(latest)
	cp, cok := parseVer(current)

	if !lok || !cok {
		return latest != current && latest > current
	}

	maxLen := len(lp)
	if len(cp) > maxLen {
		maxLen = len(cp)
	}
	for i := 0; i < maxLen; i++ {
		var lv, cv int
		if i < len(lp) {
			lv = lp[i]
		}
		if i < len(cp) {
			cv = cp[i]
		}
		if lv != cv {
			return lv > cv
		}
	}
	return false
}

func stripV(tag string) string {
	if len(tag) > 0 && (tag[0] == 'v' || tag[0] == 'V') {
		return tag[1:]
	}
	return tag
}

func parseVer(v string) ([]int, bool) {
	var segs []int
	cur := 0
	hasDigit := false
	for _, ch := range v {
		switch {
		case ch >= '0' && ch <= '9':
			cur = cur*10 + int(ch-'0')
			hasDigit = true
		case ch == '.':
			if !hasDigit {
				return nil, false
			}
			segs = append(segs, cur)
			cur = 0
			hasDigit = false
		default:
			return nil, false
		}
	}
	if !hasDigit {
		return nil, false
	}
	return append(segs, cur), true
}
