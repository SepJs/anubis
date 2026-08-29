// Package ssti detects server-side template injection by injecting
// arithmetic payloads wrapped in unique markers and checking whether the
// template engine evaluated them (result echoed between markers).
package ssti

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

func (m *Module) Name() string             { return "SSTI" }
func (m *Module) Description() string      { return "Server-Side Template Injection detection (GET/POST parameters)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// marker wraps payloads so that a raw echo can be distinguished from
// template evaluation: raw echo  → marker + "{{7*7}}" + marker
// evaluated      → marker + "49" + marker
const marker = "zqj7k3m9anubis"

type sstiPayload struct {
	wrapped   string // what we send
	evaluated string // what appears if the engine is vulnerable
	engine    string // template engine hint
}

var sstiPayloads = []sstiPayload{
	{marker + "{{7*7}}" + marker, marker + "49" + marker, "Jinja2 / Twig / Django / Nunjucks"},
	{marker + "${7*7}" + marker, marker + "49" + marker, "Freemarker / Velocity / Thymeleaf / MVEL"},
	{marker + "<%= 7*7 %>" + marker, marker + "49" + marker, "ERB (Ruby) / EJS (Node)"},
	{marker + "#{7*7}" + marker, marker + "49" + marker, "Ruby / Pug"},
	{marker + "{{7*'7'}}" + marker, marker + "7777777" + marker, "Jinja2 (differentiates from Twig)"},
	{marker + "#{7*7}" + marker, marker + "49" + marker, "Jade/Pug"},
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
		return fmt.Errorf("ssti: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	params := extractURLParams(target)

	if len(params) == 0 {
		params = []string{"name", "message", "template", "preview", "content", "text", "greeting", "email", "title", "render"}
		utils.LogDebug(cfg.Verbose, "ssti: no URL params found, testing common parameter names")
	}

	utils.LogDebug(cfg.Verbose, "ssti: testing %d parameter(s) with %d payloads", len(params), len(sstiPayloads))

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, param := range params {
		for _, p := range sstiPayloads {
			statusCode, found := testParam(client, target, param, p, httpCfg, cfg, findings)
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
	targetURL, param string,
	p sstiPayload,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
) (int, bool) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return 0, false
	}

	q := u.Query()
	q.Set(param, p.wrapped)
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

	// Confirmed only if the evaluated result appears wrapped by the marker —
	// a raw echo of "{{7*7}}" is NOT a finding.
	if strings.Contains(string(body), p.evaluated) {
		findings <- scanner.Finding{
			ID:          fmt.Sprintf("ssti-%s", param),
			Module:      "SSTI",
			Type:        scanner.FindingVulnerability,
			Title:       fmt.Sprintf("Server-Side Template Injection: %s (%s)", param, p.engine),
			Description: fmt.Sprintf("Parameter %q is injected into a server-side template engine. The arithmetic payload was evaluated server-side (evaluated result echoed between unique markers), indicating SSTI compatible with: %s", param, p.engine),
			Severity:    scanner.SeverityCritical,
			Confidence:  scanner.ConfidenceConfirmed,
			Endpoint:    targetURL,
			Parameter:   param,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Sent: %s | Response contained: %s", p.wrapped, p.evaluated),
			CVSSScore:   9.8,
			OWASPMapping: "A03:2021 – Injection",
			Remediation: fmt.Sprintf(`Server-Side Template Injection in parameter %q.

• Treat template content as code: NEVER pass user input into the template
  source itself (render_template_string(user_input) is the classic sink).
• Pass user input as template *variables*/context instead of embedding it
  in the template string.
• Choose sandboxed template engines or enable strict sandbox modes.
• Restrict engine capabilities (disable dangerous globals, filters, imports).`, param),
			VulnCode: fmt.Sprintf(`// VULNERABLE: user input becomes part of the template source
tpl := fmt.Sprintf("Hello {{ .Name | %s }}", req.FormValue("%s"))
tmpl.Execute(w, data) // template body includes attacker text`, param),
			SecureCode: fmt.Sprintf(`// SECURE: user input passed as data, not as template source
tmpl := template.Must(template.New("greet").Parse("Hello {{ .Name }}"))
tmpl.Execute(w, struct{ Name string }{req.FormValue("%s")})`, param),
			References: []string{
				"https://portswigger.net/research/server-side-template-injection",
				"https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
			},
			DiscoveredAt: time.Now(),
		}
		return statusCode, true
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
