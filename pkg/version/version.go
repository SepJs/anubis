package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	Version   = "2.0.0"
	BuildDate = "unknown"
	GitHash   = "unknown"
)

const (
	ProjectURL  = "https://github.com/SepJs/anubis"
	ReleasesAPI = "https://api.github.com/repos/SepJs/anubis/releases/latest"
	httpTimeout = 8 * time.Second
)

type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	PublishedAt string         `json:"published_at"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
	Checksum    string         `json:"checksum,omitempty"`
}

type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int    `json:"size"`
	Checksum    string `json:"checksum,omitempty"`
}

func Info() string {
	return fmt.Sprintf("Anubis v%s (build %s, commit %s)", Version, BuildDate, GitHash)
}

func FetchLatest() (*ReleaseInfo, error) {
	client := &http.Client{Timeout: httpTimeout}

	req, err := http.NewRequest(http.MethodGet, ReleasesAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("version: build request: %w", err)
	}
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

func VerifyChecksum(data []byte, expectedHex string) bool {
	hash := sha256.Sum256(data)
	computed := hex.EncodeToString(hash[:])
	return computed == expectedHex
}

func VerifyChecksumReader(r io.Reader, expectedHex string) (bool, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return false, err
	}
	computed := hex.EncodeToString(h.Sum(nil))
	return computed == expectedHex, nil
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
