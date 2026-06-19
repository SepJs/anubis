// Package version handles version metadata and update checking against GitHub releases.
package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Current build metadata. BuildDate/GitHash are meant to be overridden at
// build time via -ldflags, e.g.:
//   go build -ldflags "-X github.com/innervoid/anubis/pkg/version.GitHash=$(git rev-parse --short HEAD)"
// Left as plain vars (not consts) so -ldflags -X can set them.
var (
	Version   = "1.1.0"
	BuildDate = "unknown"
	GitHash   = "unknown"
)

const (
	ProjectURL  = "https://github.com/innervoid/anubis"
	ReleasesAPI = "https://api.github.com/repos/innervoid/anubis/releases/latest"
	httpTimeout = 8 * time.Second
)

// ReleaseInfo mirrors the subset of the GitHub releases API response we use.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	PublishedAt string         `json:"published_at"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
}

// ReleaseAsset is a single downloadable file attached to a release.
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
// It returns an error if the network is unreachable, the API rate-limits us,
// or the response can't be parsed — callers must handle that explicitly rather
// than assuming "no error means update available".
func FetchLatest() (*ReleaseInfo, error) {
	client := &http.Client{Timeout: httpTimeout}

	req, err := http.NewRequest(http.MethodGet, ReleasesAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("version: build request: %w", err)
	}
	// GitHub's API requires a User-Agent header or it returns 403.
	req.Header.Set("User-Agent", "anubis-scanner/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("version: request failed (offline or blocked?): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("version: no releases published yet at %s", ProjectURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("version: GitHub API returned status %d", resp.StatusCode)
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
		return nil, fmt.Errorf("version: response had no tag_name — unexpected API shape")
	}

	return &release, nil
}

// IsNewer reports whether latest.TagName represents a newer version than the
// currently running build. Comparison is done numerically per dot-separated
// segment (so "1.10.0" > "1.9.0", unlike a naive string compare). Versions
// that don't parse as dotted integers fall back to a direct string compare.
func IsNewer(latestTag string) bool {
	latest := normalizeTag(latestTag)
	current := normalizeTag(Version)

	lp, lok := parseSegments(latest)
	cp, cok := parseSegments(current)

	if !lok || !cok {
		return latest != current && latest > current
	}

	for i := 0; i < len(lp) || i < len(cp); i++ {
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

func normalizeTag(tag string) string {
	if len(tag) > 0 && (tag[0] == 'v' || tag[0] == 'V') {
		return tag[1:]
	}
	return tag
}

func parseSegments(v string) ([]int, bool) {
	var segments []int
	current := 0
	hasDigit := false
	for _, ch := range v {
		switch {
		case ch >= '0' && ch <= '9':
			current = current*10 + int(ch-'0')
			hasDigit = true
		case ch == '.':
			if !hasDigit {
				return nil, false
			}
			segments = append(segments, current)
			current = 0
			hasDigit = false
		default:
			return nil, false // non-numeric, non-dot character — bail to string compare
		}
	}
	if !hasDigit {
		return nil, false
	}
	segments = append(segments, current)
	return segments, true
}
