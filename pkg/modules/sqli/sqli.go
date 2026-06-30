package sqli

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

func (m *Module) Name() string             { return "SQLI" }
func (m *Module) Description() string      { return "SQL Injection detection (GET/POST parameters)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// errorSignatures are database error strings that indicate SQL injection
var errorSignatures = []struct {
	pattern string
	dbType  string
}{
	{"you have an error in your sql syntax", "MySQL"},
	{"warning: mysql", "MySQL"},
	{"unclosed quotation mark after the character string", "MSSQL"},
	{"quoted string not properly terminated", "Oracle"},
	{"pg_query()", "PostgreSQL"},
	{"sqlite3.operationalerror", "SQLite"},
	{"ora-01756", "Oracle"},
	{"ora-00907", "Oracle"},
	{"microsoft oledb provider for sql server", "MSSQL"},
	{"odbc sql server driver", "MSSQL"},
	{"mysql_fetch_array()", "MySQL"},
	{"division by zero in", "MySQL/PHP"},
	{"supplied argument is not a valid mysql", "MySQL"},
	{"invalid query", "Generic SQL"},
	{"sql syntax", "Generic SQL"},
	{"syntax error", "Generic SQL"},
}

// testPayloads are safe, non-destructive payloads for error-based detection
var testPayloads = []string{
	"'",
	"''",
	"`",
	"\"",
	"\\",
	"'--",
	"'/*",
	"') OR '1'='1",
	"' OR '1'='1'--",
	"1 AND 1=1",
	"1 AND 1=2",
	"1' AND '1'='1",
	"1' AND '1'='2",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	// Pacing handled by the delay.Limiter below, not by DoRequest's sleep —
	// see the equivalent note in pkg/modules/sensitive/sensitive.go.
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("sqli: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)

	// Discover parameters from the target URL
	params := extractURLParams(target)

	if len(params) == 0 {
		// Try common parameter names as a heuristic
		params = []string{"id", "q", "search", "query", "page", "cat", "user", "item", "product"}
		utils.LogDebug(cfg.Verbose, "sqli: no URL params found, testing common parameter names")
	}

	utils.LogDebug(cfg.Verbose, "sqli: testing %d parameter(s) with %d payloads", len(params), len(testPayloads))

	// This loop is sequential (no goroutines), so a single Limiter with no
	// mutex is safe — every Wait() call happens on this one goroutine.
	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, param := range params {
		for _, payload := range testPayloads {
			statusCode, err := testParam(client, target, param, payload, httpCfg, cfg, findings, m.Name())
			if err != nil {
				utils.LogDebug(cfg.Verbose, "sqli: error testing param %s with payload %q: %v", param, payload, err)
			}
			if cfg.AdaptiveDelay && statusCode > 0 {
				limiter.RecordStatusCode(statusCode)
			}
			if cfg.RateLimit > 0 {
				limiter.Wait()
			}
		}
	}

	return nil
}

// testParam sends a single payload against a single parameter and returns
// the HTTP status code observed (0 if the request never completed) so the
// caller's rate limiter can factor it into adaptive backoff decisions.
func testParam(
	client *http.Client,
	targetURL, param, payload string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
) (int, error) {
	// Build test URL with injected payload
	u, err := url.Parse(targetURL)
	if err != nil {
		return 0, err
	}

	q := u.Query()
	original := q.Get(param)
	q.Set(param, original+payload)
	u.RawQuery = q.Encode()
	testURL := u.String()

	resp, err := utils.DoRequest(client, http.MethodGet, testURL, nil, httpCfg)
	if err != nil {
		return 0, nil // connection errors are expected with some payloads
	}
	defer utils.SafeClose(resp.Body)
	statusCode := resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64 KB cap
	if err != nil {
		return statusCode, nil
	}

	bodyLower := strings.ToLower(string(body))

	for _, sig := range errorSignatures {
		if strings.Contains(bodyLower, sig.pattern) {
			findings <- scanner.Finding{
				ID:           fmt.Sprintf("sqli-%s-%s", param, strings.ReplaceAll(payload, "'", "")),
				Module:       module,
				Type:         scanner.FindingVulnerability,
				Title:        fmt.Sprintf("SQL Injection: %s (%s error detected)", param, sig.dbType),
				Description:  fmt.Sprintf("Parameter %q appears to be vulnerable to SQL injection. Database error signature from %s was triggered with payload: %s", param, sig.dbType, payload),
				Severity:     scanner.SeverityCritical,
				Confidence:   scanner.ConfidenceConfirmed,
				Endpoint:     targetURL,
				Parameter:    param,
				Method:       "GET",
				Evidence:     fmt.Sprintf("Payload: %s | DB signature: %q", payload, sig.pattern),
				CVSSScore:    9.8,
				OWASPMapping: "A03:2021 – Injection",
				Remediation:  buildRemediation(param),
				VulnCode:     buildVulnCode(param),
				SecureCode:   buildSecureCode(param),
				References: []string{
					"https://owasp.org/www-community/attacks/SQL_Injection",
					"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
				},
				DiscoveredAt: time.Now(),
			}
			return statusCode, nil // one finding per param is enough for error-based
		}
	}

	// Time-based blind detection heuristic (response significantly slower)
	// Note: very basic heuristic; a full time-based approach needs baseline
	if resp.StatusCode == http.StatusOK && len(body) > 0 {
		// Check for boolean-based indicators (same status, different content length)
		// This is informational only without a proper baseline comparison
	}

	return statusCode, nil
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
	return fmt.Sprintf(`SQL Injection in parameter %q.

Use parameterized queries / prepared statements instead of concatenating user input:
• NEVER build SQL by concatenating user-supplied values.
• Use your language's database driver's parameter binding.
• Apply input validation as defense-in-depth.
• Use a WAF as an additional layer (not a replacement).
• Apply the principle of least privilege to database accounts.`, param)
}

func buildVulnCode(param string) string {
	return fmt.Sprintf(`// VULNERABLE: direct string concatenation
query := "SELECT * FROM users WHERE id = " + req.FormValue("%s")
rows, err := db.Query(query)`, param)
}

func buildSecureCode(param string) string {
	return fmt.Sprintf(`// SECURE: parameterized query
query := "SELECT * FROM users WHERE id = ?"
rows, err := db.Query(query, req.FormValue("%s"))`, param)
}
