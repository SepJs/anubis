// Package sqli detects SQL injection using error signatures with baseline
// comparison, boolean-based blind, and time-based blind techniques.
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
func (m *Module) Description() string      { return "SQL Injection detection (error-based, boolean blind, time blind)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

var errorSignatures = []struct {
	pattern string
	dbType  string
}{
	{"you have an error in your sql syntax", "MySQL"},
	{"warning: mysql", "MySQL"},
	{"mysql_fetch_array()", "MySQL"},
	{"supplied argument is not a valid mysql", "MySQL"},
	{"unclosed quotation mark after the character string", "MSSQL"},
	{"microsoft oledb provider for sql server", "MSSQL"},
	{"odbc sql server driver", "MSSQL"},
	{"quoted string not properly terminated", "Oracle"},
	{"ora-01756", "Oracle"},
	{"ora-00907", "Oracle"},
	{"pg_query()", "PostgreSQL"},
	{"pg_sleep", "PostgreSQL"},
	{"sqlite3.operationalerror", "SQLite"},
	{"unrecognized token", "SQLite"},
	{"division by zero in", "MySQL/PHP"},
	{"invalid query", "Generic SQL"},
	{"sql syntax", "Generic SQL"},
}

var errorPayloads = []string{
	"'",
	"\"",
	"`",
	"\\",
	"'--",
	"'/*",
	"1'",
	"1\"",
}

// booleanPairs: true-payload should return a response similar to baseline,
// false-payload should differ (different status or significantly different length).
var booleanPairs = []struct{ trueP, falseP string }{
	{"1 AND 1=1", "1 AND 1=2"},
	{"1' AND '1'='1", "1' AND '1'='2"},
	{"1') AND ('1'='1", "1') AND ('1'='2"},
}

var timePayloads = []struct {
	payload string
	dbType  string
	seconds int
}{
	{"1' AND SLEEP(3)-- ", "MySQL", 3},
	{"1 AND SLEEP(3)", "MySQL", 3},
	{"1'; SELECT pg_sleep(3)-- ", "PostgreSQL", 3},
	{"1' WAITFOR DELAY '0:0:3'-- ", "MSSQL", 3},
}

type response struct {
	status  int
	body    string
	elapsed time.Duration
}

func fetch(client *http.Client, rawURL string, httpCfg utils.HTTPConfig) (*response, error) {
	start := time.Now()
	resp, err := utils.DoRequest(client, http.MethodGet, rawURL, nil, httpCfg)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer utils.SafeClose(resp.Body)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return &response{status: resp.StatusCode, elapsed: elapsed}, nil
	}
	return &response{status: resp.StatusCode, body: strings.ToLower(string(body)), elapsed: elapsed}, nil
}

func inject(targetURL, param, value string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func containsAny(body string, patterns []string) (string, bool) {
	for _, p := range patterns {
		if strings.Contains(body, p) {
			return p, true
		}
	}
	return "", false
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
		return fmt.Errorf("sqli: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	targets := utils.EndpointList(cfg, target)

	utils.LogDebug(cfg.Verbose, "sqli: %d target(s)", len(targets))

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)
	wait := func(status int) {
		if cfg.AdaptiveDelay && status > 0 {
			limiter.RecordStatusCode(status)
		}
		if cfg.RateLimit > 0 {
			limiter.Wait()
		}
	}

	for _, tgt := range targets {
		params := extractURLParams(tgt)
		if len(params) == 0 {
			if tgt != target {
				continue
			}
			params = []string{"id", "q", "search", "query", "page", "cat", "user", "item", "product"}
			utils.LogDebug(cfg.Verbose, "sqli: no URL params on %s, testing common parameter names", tgt)
		}

		for _, param := range params {
			u, err := url.Parse(tgt)
			if err != nil {
				continue
			}
			original := u.Query().Get(param)

			// --- baseline ---
			base, err := fetch(client, tgt, httpCfg)
			if err != nil || base.status == 0 {
				continue // endpoint unreachable
			}
			wait(base.status)

			found := false

			// --- 1) error-based with baseline comparison ---
			for _, payload := range errorPayloads {
				testURL, err := inject(tgt, param, original+payload)
				if err != nil {
					continue
				}
				r, err := fetch(client, testURL, httpCfg)
				if err != nil {
					continue
				}
				wait(r.status)

				if sig, ok := containsAny(r.body, sigPatterns()); ok && !strings.Contains(base.body, sig) {
					emitErrorBased(findings, m.Name(), tgt, param, payload, sig, base, r)
					found = true
					break
				}
			}
			if found {
				continue
			}

			// --- 2) boolean-based blind ---
			for _, pair := range booleanPairs {
				tURL, _ := inject(tgt, param, original+pair.trueP)
				fURL, _ := inject(tgt, param, original+pair.falseP)

				tr, err1 := fetch(client, tURL, httpCfg)
				fr, err2 := fetch(client, fURL, httpCfg)
				if err1 != nil || err2 != nil {
					continue
				}
				wait(tr.status)
				wait(fr.status)

				if tr.status != fr.status || tr.status != http.StatusOK {
					continue
				}
				lenTrue, lenFalse := len(tr.body), len(fr.body)
				lenBase := len(base.body)
				// true ≈ baseline, false differs meaningfully
				similarToBase := abs(lenTrue-lenBase) <= lenBase/10+32
				differsFromBase := abs(lenFalse-lenTrue) > (lenTrue+lenFalse)/10+64
				if similarToBase && differsFromBase {
					emitBooleanBlind(findings, m.Name(), tgt, param, pair, lenBase, lenTrue, lenFalse)
					found = true
					break
				}
			}
			if found {
				continue
			}

			// --- 3) time-based blind (skipped in ghost mode) ---
			if !cfg.GhostMode {
				for _, tp := range timePayloads {
					testURL, _ := inject(tgt, param, original+tp.payload)
					r1, err := fetch(client, testURL, httpCfg)
					if err != nil {
						continue
					}
					wait(r1.status)

					threshold := time.Duration(tp.seconds)*900*time.Millisecond + 1*time.Second
					if r1.elapsed < threshold || r1.elapsed < base.elapsed+2*time.Second {
						continue
					}

					// verification: repeat once — a real sleep-based delay reproduces
					r2, err := fetch(client, testURL, httpCfg)
					if err != nil || r2.elapsed < threshold {
						continue
					}
					wait(r2.status)

					emitTimeBlind(findings, m.Name(), tgt, param, tp, r1.elapsed, r2.elapsed)
					found = true
					break
				}
			}
		}
	}

	return nil
}

func sigPatterns() []string {
	patterns := make([]string, len(errorSignatures))
	for i, s := range errorSignatures {
		patterns[i] = s.pattern
	}
	return patterns
}

func dbTypeFor(sig string) string {
	for _, s := range errorSignatures {
		if s.pattern == sig {
			return s.dbType
		}
	}
	return "unknown"
}

func emitErrorBased(findings chan<- scanner.Finding, module, targetURL, param, payload, sig string, base, r *response) {
	findings <- scanner.Finding{
		ID:         fmt.Sprintf("sqli-error-%s", param),
		Module:     module,
		Type:       scanner.FindingVulnerability,
		Title:      fmt.Sprintf("SQL Injection: %s (%s error detected)", param, dbTypeFor(sig)),
		Description: fmt.Sprintf("Parameter %q appears vulnerable to SQL injection. Database error signature from %s was triggered with payload %q and is NOT present in the baseline response — indicating the error is caused by the injected payload.", param, dbTypeFor(sig), payload),
		Severity:     scanner.SeverityCritical,
		Confidence:   scanner.ConfidenceConfirmed,
		Endpoint:     targetURL,
		Parameter:    param,
		Method:       "GET",
		Evidence:     fmt.Sprintf("Payload: %s | DB signature: %q (absent in baseline response)", payload, sig),
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
}

func emitBooleanBlind(findings chan<- scanner.Finding, module, targetURL, param string, pair struct{ trueP, falseP string }, lenBase, lenTrue, lenFalse int) {
	findings <- scanner.Finding{
		ID:          fmt.Sprintf("sqli-bool-%s", param),
		Module:      module,
		Type:        scanner.FindingVulnerability,
		Title:       fmt.Sprintf("SQL Injection (boolean-based blind): %s", param),
		Description: fmt.Sprintf("Parameter %q shows a differential response between a condition that evaluates true (%q → %d bytes) and false (%q → %d bytes), while the true response matches the baseline (%d bytes). This is characteristic of boolean-based blind SQL injection.", param, pair.trueP, lenTrue, pair.falseP, lenFalse, lenBase),
		Severity:    scanner.SeverityHigh,
		Confidence:  scanner.ConfidenceSuspected,
		Endpoint:    targetURL,
		Parameter:   param,
		Method:      "GET",
		Evidence:    fmt.Sprintf("TRUE payload %q → %d bytes | FALSE payload %q → %d bytes | baseline → %d bytes", pair.trueP, lenTrue, pair.falseP, lenFalse, lenBase),
		CVSSScore:   8.6,
		OWASPMapping: "A03:2021 – Injection",
		Remediation: buildRemediation(param),
		VulnCode:    buildVulnCode(param),
		SecureCode:  buildSecureCode(param),
		References: []string{
			"https://portswigger.net/web-security/sql-injection/blind",
		},
		DiscoveredAt: time.Now(),
	}
}

func emitTimeBlind(findings chan<- scanner.Finding, module, targetURL, param, tp struct {
	payload string
	dbType  string
	seconds int
}, d1, d2 time.Duration) {
	findings <- scanner.Finding{
		ID:          fmt.Sprintf("sqli-time-%s", param),
		Module:      module,
		Type:        scanner.FindingVulnerability,
		Title:       fmt.Sprintf("SQL Injection (time-based blind): %s (%s)", param, tp.dbType),
		Description: fmt.Sprintf("Parameter %q shows reproducible response delay (%.1fs and %.1fs vs baseline) with %s time-delay payload — characteristic of time-based blind SQL injection. Verified with two consecutive requests.", param, d1.Seconds(), d2.Seconds(), tp.dbType),
		Severity:    scanner.SeverityCritical,
		Confidence:  scanner.ConfidenceConfirmed,
		Endpoint:    targetURL,
		Parameter:   param,
		Method:      "GET",
		Evidence:    fmt.Sprintf("Payload: %s | delay1: %.1fs | delay2: %.1fs", tp.payload, d1.Seconds(), d2.Seconds()),
		CVSSScore:   9.1,
		OWASPMapping: "A03:2021 – Injection",
		Remediation: buildRemediation(param),
		VulnCode:    buildVulnCode(param),
		SecureCode:  buildSecureCode(param),
		References: []string{
			"https://portswigger.net/web-security/sql-injection/blind",
		},
		DiscoveredAt: time.Now(),
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
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
