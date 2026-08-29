// Package openredirect detects unvalidated URL redirects by injecting a
// canary host into parameters and checking whether the server redirects
// (3xx Location, meta-refresh, or JS location) to it.
package openredirect

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

func (m *Module) Name() string             { return "OPENREDIRECT" }
func (m *Module) Description() string      { return "Open Redirect detection via canary host (GET parameters)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// canaryHost uses the reserved .invalid TLD — guaranteed non-resolvable,
// so the check is purely string-based with zero network side effects.
const canaryHost = "anubis-orc.invalid"

var redirectPayloads = []string{
	"https://" + canaryHost,
	"//" + canaryHost,
	"/\\" + canaryHost,
	"https:/" + canaryHost,
	"https%3A%2F%2F" + canaryHost,
	"%2F%2F" + canaryHost,
	"https://" + canaryHost + "#",
	"https://" + canaryHost + "?",
	"https://trusted.com@" + canaryHost + "/",
	"https://" + canaryHost + ".trusted.com/",
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
		return fmt.Errorf("openredirect: build client: %w", err)
	}

	// CRITICAL: do not follow redirects — we need the *first* response's
	// Location header. ErrUseLastResponse returns the 3xx response itself.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	target := utils.NormalizeTarget(cfg.Target)
	params := extractURLParams(target)

	if len(params) == 0 {
		params = []string{"url", "redirect", "next", "goto", "return", "returnTo", "r", "u", "continue", "dest", "destination", "link", "target", "out", "view"}
		utils.LogDebug(cfg.Verbose, "openredirect: no URL params found, testing common parameter names")
	}

	utils.LogDebug(cfg.Verbose, "openredirect: testing %d parameter(s) with %d payloads", len(params), len(redirectPayloads))

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, param := range params {
		for _, payload := range redirectPayloads {
			statusCode, found := testParam(client, target, param, payload, httpCfg, cfg, findings)
			if cfg.AdaptiveDelay && statusCode > 0 {
				limiter.RecordStatusCode(statusCode)
			}
			if cfg.RateLimit > 0 {
				limiter.Wait()
			}
			if found {
				break
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
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	testURL := u.String()

	resp, err := utils.DoRequest(client, http.MethodGet, testURL, nil, httpCfg)
	if err != nil {
		return 0, false
	}
	defer utils.SafeClose(resp.Body)
	statusCode := resp.StatusCode

	// Method 1: 3xx Location header contains the canary host
	loc := resp.Header.Get("Location")
	if isRedirectStatus(statusCode) && strings.Contains(strings.ToLower(loc), canaryHost) {
		emitFinding(cfg, findings, targetURL, param, payload,
			fmt.Sprintf("HTTP %d redirect to: %s", statusCode, loc))
		return statusCode, true
	}

	// Method 2: meta-refresh or JS redirect in the body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err == nil {
		bodyLower := strings.ToLower(string(body))
		if (strings.Contains(bodyLower, "<meta http-equiv=\"refresh\"") ||
			strings.Contains(bodyLower, "location.href") ||
			strings.Contains(bodyLower, "location.replace") ||
			strings.Contains(bodyLower, "window.location")) &&
			strings.Contains(bodyLower, canaryHost) {
			emitFinding(cfg, findings, targetURL, param, payload,
				"Client-side redirect (meta-refresh/JS) containing canary host")
			return statusCode, true
		}
	}

	return statusCode, false
}

func isRedirectStatus(code int) bool {
	return code == http.StatusMovedPermanently || code == http.StatusFound ||
		code == http.StatusSeeOther || code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

func emitFinding(
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	targetURL, param, payload, evidence string,
) {
	findings <- scanner.Finding{
		ID:          fmt.Sprintf("openredirect-%s", param),
		Module:      "OPENREDIRECT",
		Type:        scanner.FindingVulnerability,
		Title:       fmt.Sprintf("Open Redirect: %s", param),
		Description: fmt.Sprintf("Parameter %q redirects the user to an attacker-controlled URL without validation. An attacker can craft a link like %s?%s=<payload> to phish users via the trusted domain.", targetURL, targetURL, param),
		Severity:    scanner.SeverityMedium,
		Confidence:  scanner.ConfidenceConfirmed,
		Endpoint:    targetURL,
		Parameter:   param,
		Method:      "GET",
		Evidence:    fmt.Sprintf("Payload: %s | %s", payload, evidence),
		CVSSScore:   6.1,
		OWASPMapping: "A01:2021 – Broken Access Control (Unvalidated Redirects)",
		Remediation: fmt.Sprintf(`Open Redirect in parameter %q.

• Never redirect based on raw user input. Validate against a strict allowlist
  of permitted destinations (exact URLs or exact hosts).
• Prefer relative-path-only redirects: reject anything that starts with
  "//", "/", "\", "http:", "https:" or contains a scheme.
• If external redirects are required, use an intermediate confirmation page
  ("You are leaving <site>") or signed tokens (HMAC of the destination).
• Validate AFTER decoding: check both the raw and URL-decoded value.`, param),
		VulnCode: fmt.Sprintf(`// VULNERABLE: redirect target taken from user input
next := req.FormValue("%s")
http.Redirect(w, r, next, http.StatusFound)`, param),
		SecureCode: fmt.Sprintf(`// SECURE: allowlist of approved destinations
var allowed = map[string]bool{"/dashboard": true, "/profile": true}
next := req.FormValue("%s")
if !allowed[next] {
	next = "/dashboard" // safe default
}
http.Redirect(w, r, next, http.StatusFound)`, param),
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
		},
		DiscoveredAt: time.Now(),
	}
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
