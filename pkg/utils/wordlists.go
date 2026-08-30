package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LoadWordlist reads a wordlist file (one entry per line), ignoring blank
// lines and # comments. Entries are normalized to have a leading slash.
// If path is empty or unreadable, the fallback list is returned unchanged.
func LoadWordlist(path string, fallback []string) []string {
	if path == "" {
		return fallback
	}

	data, err := os.ReadFile(path)
	if err != nil {
		LogWarn("wordlist: cannot read %s (%v) — using built-in list", path, err)
		return fallback
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		LogWarn("wordlist: read error in %s (%v) — using built-in list", path, err)
		return fallback
	}
	if len(out) == 0 {
		LogWarn("wordlist: %s is empty — using built-in list", path)
		return fallback
	}

	LogInfo("wordlist: loaded %d entries from %s", len(out), path)
	return out
}

// CertTransparencySubdomains queries the crt.sh CT log aggregator for
// observed subdomains of the given domain. Returns nil on any error —
// callers must treat this as best-effort (fail-open).
func CertTransparencySubdomains(domain string) ([]string, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("crt.sh: read body: %w", err)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh: parse: %w", err)
	}

	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimSuffix(name, ".")
			if name == "" || strings.Contains(name, "*") {
				continue
			}
			// must be a subdomain of the queried domain
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, strings.TrimSuffix(name, "."+domain))
			}
		}
	}
	return out, nil
}
