// Package xss detects reflected cross-site scripting (XSS) vulnerabilities
// by injecting uniquely-marked probes and verifying unescaped reflection
// with context classification.
package xss

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

func (m *Module) Name() string             { return "XSS" }
func (m *Module) Description() string      { return "Cross-Site Scripting (Reflected) detection with context analysis" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

var reflectedPayloads = []struct {
	payload string
	marker  string
}{
	{`<anubis-xss-probe>`, `<anubis-xss-probe>`},
	{`"><anubis-probe`, `"><anubis-probe`},
	{`'><anubis-probe`, `'><anubis-probe`},
	{`anubis"xss'probe`, `anubis"xss'probe`},
	{`<ScRiPt>anubisXSSProbe</ScRiPt>`, `anubisxssprobe`},
	{`javascript:anubisProbe`, `javascript:anubisprobe`},
	{`<img src=x onerror=anubisProbe>`, `onerror=anubisprobe`},
	{`<svg onload=anubisProbe>`, `onerror=anubisprobe`},
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
		return fmt.Errorf("xss: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	targets := utils.EndpointList(cfg, target)

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, tgt := range targets {
		params := extractURLParams(tgt)
		if len(params) == 0 {
			if tgt != target {
				continue
			}
			params = []string{"q", "search", "query", "name", "comment", "message", "page", "redirect", "email"}
		}

		for _, param := range params {
			for _, pp := range reflectedPayloads {
				statusCode, found := testParam(client, tgt, param, pp.payload, pp.marker, httpCfg, cfg, findings, m.Name())
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
	}

	return nil
}

func testParam(
	client *http.Client,
	targetURL, param, payload, marker string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
) (int, bool) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return 0, false
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()

	resp, err := utils.DoRequest(client, http.MethodGet, u.String(), nil, httpCfg)
	if err != nil {
		return 0, false
	}
	defer utils.SafeClose(resp.Body)
	statusCode := resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return statusCode, false
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)
	markerLower := strings.ToLower(marker)

	// KEY CHECK: the raw (unescaped) marker must be present, and the raw
	// payload must NOT be present only in escaped form. If only the
	// URL-encoded payload appears, output encoding is in place → no finding.
	if !strings.Contains(bodyLower, markerLower) {
		return statusCode, false
	}
	if isEncoded(bodyStr, payload) {
		return statusCode, false
	}

	context := detectReflectionContext(bodyLower, markerLower)
	severity := scanner.SeverityHigh
	if context == "script" {
		severity = scanner.SeverityCritical
	}

	findings <- scanner.Finding{
		ID:           fmt.Sprintf("xss-reflected-%s", param),
		Module:       module,
		Type:         scanner.FindingVulnerability,
		Title:        fmt.Sprintf("Reflected XSS: parameter %q (%s context)", param, context),
		Description:  fmt.Sprintf("Parameter %q reflects user input unescaped in the response (context: %s). Verify exploitability in a browser; scripted payloads in this context may execute.", param, context),
		Severity:     severity,
		Confidence:   scanner.ConfidenceConfirmed,
		Endpoint:     targetURL,
		Parameter:    param,
		Method:       "GET",
		Evidence:     fmt.Sprintf("Payload %q found unescaped in response body (context: %s)", payload, context),
		CVSSScore:    7.4,
		OWASPMapping: "A03:2021 – Injection",
		Remediation:  buildRemediation(param),
		VulnCode:     buildVulnCode(param),
		SecureCode:   buildSecureCode(param),
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
		DiscoveredAt: time.Now(),
	}
	return statusCode, true
}

func isEncoded(body, payload string) bool {
	encoded := url.QueryEscape(payload)
	return strings.Contains(body, encoded) && !strings.Contains(body, payload)
}

func detectReflectionContext(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx < 0 {
		return "html"
	}
	start := idx - 200
	if start < 0 {
		start = 0
	}
	surrounding := body[start:idx]

	if strings.Contains(surrounding, "<script") && !strings.Contains(surrounding, "</script") {
		return "script"
	}
	if strings.Contains(surrounding, "href=") || strings.Contains(surrounding, "src=") || strings.Contains(surrounding, "action=") {
		return "url"
	}
	singleQuotes := strings.Count(surrounding, "'") % 2
	doubleQuotes := strings.Count(surrounding, "\"") % 2
	if singleQuotes != 0 || doubleQuotes != 0 {
		return "attribute"
	}
	return "html"
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

func buildRemediation(param string) string {
	return fmt.Sprintf(`XSS in parameter %q.

• HTML-encode all user output: use your framework's built-in escaping.
• Apply a strict Content-Security-Policy header.
• Never insert user data directly into JavaScript contexts.
• Use framework templating engines (they escape by default).
• Validate and sanitize input on the server side.`, param)
}

func buildVulnCode(param string) string {
	return fmt.Sprintf(`// VULNERABLE: unencoded user input in HTML output
value := r.URL.Query().Get("%s")
fmt.Fprintf(w, "<div>Search: %%s</div>", value)`, param)
}

func buildSecureCode(param string) string {
	return fmt.Sprintf(`// SECURE: HTML-encoded output
import "html"
value := r.URL.Query().Get("%s")
fmt.Fprintf(w, "<div>Search: %%s</div>", html.EscapeString(value))`, param)
}
