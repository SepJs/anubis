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
func (m *Module) Description() string      { return "Cross-Site Scripting (Reflected/Stored) detection" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// reflectedPayloads are XSS probes that help detect reflection without being harmful
// Using unique markers that we look for in the response
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
}

// contextIndicators help classify where the reflection occurs
var contextIndicators = map[string]string{
	"attribute": "Reflected inside an HTML attribute — high XSS risk",
	"script":    "Reflected inside a <script> block — critical XSS risk",
	"html":      "Reflected in HTML body context",
	"url":       "Reflected in URL/href context",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	// Pacing handled by the shared delay.Limiter below, not by DoRequest's
	// own sleep — see the equivalent note in pkg/modules/sensitive/sensitive.go.
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("xss: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	params := extractURLParams(target)

	if len(params) == 0 {
		params = []string{"q", "search", "query", "s", "term", "keyword", "name", "message", "comment", "text"}
		utils.LogDebug(cfg.Verbose, "xss: no URL params found, testing common parameter names")
	}

	utils.LogDebug(cfg.Verbose, "xss: testing %d parameter(s) with %d payloads", len(params), len(reflectedPayloads))

	// Sequential loop (no goroutines) — a single Limiter with no mutex is safe.
	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, param := range params {
		for _, p := range reflectedPayloads {
			if err := testReflection(client, target, param, p.payload, p.marker, httpCfg, cfg, findings, m.Name(), limiter); err != nil {
				utils.LogDebug(cfg.Verbose, "xss: error testing param %s: %v", param, err)
			}
		}
	}

	// Also test common search/input endpoints
	commonEndpoints := []string{"/search", "/comment", "/feedback", "/contact"}
	for _, ep := range commonEndpoints {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		u.Path = strings.TrimRight(u.Path, "/") + ep
		u.RawQuery = ""
		testURL := u.String()
		for _, p := range reflectedPayloads[:2] { // limit endpoint fuzzing
			if err := testFormReflection(client, testURL, p.payload, p.marker, httpCfg, cfg, findings, m.Name(), limiter); err != nil {
				utils.LogDebug(cfg.Verbose, "xss: error testing endpoint %s: %v", testURL, err)
			}
		}
	}

	return nil
}

// testReflection probes one parameter with one payload, paces via limiter
// afterward, and feeds the observed status code back in when adaptive
// delay is enabled.
func testReflection(
	client *http.Client,
	targetURL, param, payload, marker string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
	limiter *delay.Limiter,
) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	testURL := u.String()

	resp, err := utils.DoRequest(client, http.MethodGet, testURL, nil, httpCfg)
	if err != nil {
		if cfg.RateLimit > 0 {
			limiter.Wait()
		}
		return nil
	}
	defer utils.SafeClose(resp.Body)

	if cfg.AdaptiveDelay {
		limiter.RecordStatusCode(resp.StatusCode)
	}
	if cfg.RateLimit > 0 {
		limiter.Wait()
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)
	markerLower := strings.ToLower(marker)

	if strings.Contains(bodyLower, markerLower) {
		context := detectReflectionContext(bodyLower, markerLower)
		severity := scanner.SeverityHigh
		if context == "script" {
			severity = scanner.SeverityCritical
		}

		// Check if it appears to be encoded (lower confidence if so)
		confidence := scanner.ConfidenceConfirmed
		if isEncoded(bodyStr, payload) {
			confidence = scanner.ConfidenceSuspected
		}

		findings <- scanner.Finding{
			ID:           fmt.Sprintf("xss-reflected-%s", param),
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Reflected XSS: parameter %q", param),
			Description:  fmt.Sprintf("Parameter %q reflects user input without encoding in the response. %s. Payload was reflected in: %s context.", param, contextIndicators[context], context),
			Severity:     severity,
			Confidence:   confidence,
			Endpoint:     targetURL,
			Parameter:    param,
			Method:       "GET",
			Evidence:     fmt.Sprintf("Payload %q found reflected in response body (context: %s)", payload, context),
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
	}

	return nil
}

func testFormReflection(
	client *http.Client,
	targetURL, payload, marker string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
	limiter *delay.Limiter,
) error {
	// Test via GET with common param names
	testParams := []string{"q", "search", "query"}
	for _, p := range testParams {
		u, _ := url.Parse(targetURL)
		q := u.Query()
		q.Set(p, payload)
		u.RawQuery = q.Encode()

		resp, err := utils.DoRequest(client, http.MethodGet, u.String(), nil, httpCfg)
		if err != nil {
			if cfg.RateLimit > 0 {
				limiter.Wait()
			}
			continue
		}

		if cfg.AdaptiveDelay {
			limiter.RecordStatusCode(resp.StatusCode)
		}
		if cfg.RateLimit > 0 {
			limiter.Wait()
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		utils.SafeClose(resp.Body)
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(marker)) {
			findings <- scanner.Finding{
				ID:           fmt.Sprintf("xss-reflected-endpoint-%s-%s", strings.ReplaceAll(targetURL, "/", "-"), p),
				Module:       module,
				Type:         scanner.FindingVulnerability,
				Title:        fmt.Sprintf("Reflected XSS at endpoint: %s (param: %s)", targetURL, p),
				Description:  fmt.Sprintf("XSS reflection detected at %s via parameter %q", targetURL, p),
				Severity:     scanner.SeverityHigh,
				Confidence:   scanner.ConfidenceSuspected,
				Endpoint:     targetURL,
				Parameter:    p,
				Method:       "GET",
				Evidence:     fmt.Sprintf("Payload reflected: %s", payload),
				CVSSScore:    7.4,
				OWASPMapping: "A03:2021 – Injection",
				Remediation:  buildRemediation(p),
				VulnCode:     buildVulnCode(p),
				SecureCode:   buildSecureCode(p),
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

func detectReflectionContext(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx < 0 {
		return "html"
	}
	// Look at surrounding context
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
	// Count unclosed quotes — attribute context
	singleQuotes := strings.Count(surrounding, "'") % 2
	doubleQuotes := strings.Count(surrounding, "\"") % 2
	if singleQuotes != 0 || doubleQuotes != 0 {
		return "attribute"
	}
	return "html"
}

func isEncoded(body, payload string) bool {
	encoded := url.QueryEscape(payload)
	return strings.Contains(body, encoded) && !strings.Contains(body, payload)
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
