// Package brute_force tests for default credentials and weak authentication
// by probing login endpoints with common username/password pairs.
package brute_force

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

func (m *Module) Name() string             { return "BRUTE_FORCE" }
func (m *Module) Description() string      { return "Default credential testing and brute-force (configurable)" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// defaultCredentials are common default credentials to test
var defaultCredentials = []struct{ user, pass string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", ""},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"root", "root"},
	{"root", "toor"},
	{"root", ""},
	{"user", "user"},
	{"user", "password"},
	{"guest", "guest"},
	{"test", "test"},
	{"demo", "demo"},
}

// loginPaths to probe for login forms
var loginPaths = []string{
	"/login",
	"/admin/login",
	"/administrator/login",
	"/wp-login.php",
	"/admin",
	"/user/login",
	"/signin",
	"/auth/login",
	"/panel",
	"/cp",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	if cfg.AuthStrategy == "" || cfg.AuthStrategy == "none" {
		utils.LogDebug(cfg.Verbose, "brute_force: skipped (auth strategy is none)")
		return nil
	}

	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	// Pacing now lives entirely in the delay.Limiter below — leave this at 0
	// so DoRequest's internal sleep doesn't stack with it. The "more
	// conservative for brute force" multiplier from the old fixed-delay
	// approach is preserved as a 3x base delay passed into FromConfig instead.
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("brute_force: build client: %w", err)
	}

	baseURL := strings.TrimRight(utils.NormalizeTarget(cfg.Target), "/")

	// Find login endpoints
	loginURL := findLoginEndpoint(client, baseURL, httpCfg, cfg)
	if loginURL == "" {
		utils.LogDebug(cfg.Verbose, "brute_force: no login endpoint found")
		return nil
	}

	utils.LogDebug(cfg.Verbose, "brute_force: found login endpoint at %s", loginURL)

	// Credential attempts run sequentially (deliberately — concurrent login
	// attempts against the same account is itself a detectable, aggressive
	// pattern this tool tries to avoid). A single Limiter with no mutex is
	// safe under that sequential execution. Base delay is 3x the configured
	// rate limit, matching the original module's conservatism for auth endpoints.
	limiter := delay.FromConfig(cfg.RateLimit*3, cfg.DelayStrategy, cfg.MaxDelayMs)

	// If credentials were explicitly provided, just verify them
	if cfg.Username != "" && cfg.Password != "" {
		testCredential(client, loginURL, cfg.Username, cfg.Password, httpCfg, cfg, findings, m.Name(), limiter)
		return nil
	}

	// Default credential strategy
	if cfg.AuthStrategy == "defaults" || cfg.AuthStrategy == "combined" {
		protectionDetected := false
		lockoutCount := 0

		for _, cred := range defaultCredentials {
			result := testCredential(client, loginURL, cred.user, cred.pass, httpCfg, cfg, findings, m.Name(), limiter)
			if result == "blocked" {
				lockoutCount++
				// Feed the block signal into the limiter regardless of
				// --adaptive-delay: a detected lockout/rate-limit response
				// is exactly the case the limiter's backoff exists for, and
				// continuing to hammer a blocking endpoint at full speed
				// makes detection by the target more likely, not less.
				limiter.RecordRetry()
				if lockoutCount >= 3 {
					protectionDetected = true
					break
				}
			} else {
				limiter.RecordSuccess()
			}
		}

		if protectionDetected {
			if cfg.Level >= scanner.Level3 {
				if !utils.AskBruteForce() {
					utils.LogInfo("Brute-force skipped by user choice.")
					return nil
				}
			} else {
				utils.LogWarn("Brute-force protection detected. Skipping further attempts at Level %d.", cfg.Level)
				findings <- scanner.Finding{
					ID:           "brute-protection-detected",
					Module:       m.Name(),
					Type:         scanner.FindingInformational,
					Title:        "Brute-Force Protection Detected",
					Description:  "The login endpoint appears to have rate-limiting or account lockout protection in place.",
					Severity:     scanner.SeverityInfo,
					Confidence:   scanner.ConfidenceConfirmed,
					Endpoint:     loginURL,
					Remediation:  "Good: brute-force protection is active. Ensure lockout thresholds are appropriately low (e.g., 5-10 attempts).",
					DiscoveredAt: time.Now(),
				}
				return nil
			}
		}
	}

	// Wordlist brute-force (Level 3, bruteforce or combined strategy)
	if cfg.Level >= scanner.Level3 && (cfg.AuthStrategy == "bruteforce" || cfg.AuthStrategy == "combined") {
		if cfg.Wordlist == "" {
			utils.LogWarn("brute_force: --wordlist not provided, skipping wordlist attack")
		}
		// Wordlist parsing would be implemented here when a file is provided
		// Skipping implementation without a wordlist path
	}

	return nil
}

// testCredential tests a single credential pair and returns "success", "failed", or "blocked".
// limiter paces the request that matters most here — the POST login attempt
// itself, since that's the request a target's auth rate-limiting actually
// watches, not the initial GET of the login page.
func testCredential(
	client *http.Client,
	loginURL, username, password string,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
	limiter *delay.Limiter,
) string {
	// First GET the login page to capture CSRF token and form fields
	resp, err := utils.DoRequest(client, http.MethodGet, loginURL, nil, httpCfg)
	if err != nil {
		return "failed"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	utils.SafeClose(resp.Body)

	// Check for rate limiting / lockout indicators before attempting
	statusCode := resp.StatusCode
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	if statusCode == http.StatusTooManyRequests || strings.Contains(bodyLower, "too many") || strings.Contains(bodyLower, "locked out") {
		return "blocked"
	}

	// Try to identify the form action URL
	formAction := extractFormAction(bodyStr, loginURL)

	// Build form data
	formData := url.Values{}
	formData.Set(guessUsernameField(bodyStr), username)
	formData.Set(guessPasswordField(bodyStr), password)

	// Extract CSRF token if present
	csrfToken := extractCSRFToken(bodyStr)
	if csrfToken != "" {
		formData.Set(guessCSRFField(bodyStr), csrfToken)
	}

	if cfg.RateLimit > 0 {
		limiter.Wait()
	}

	postResp, err := client.PostForm(formAction, formData)
	if err != nil {
		return "failed"
	}
	postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 64*1024))
	utils.SafeClose(postResp.Body)

	postBodyLower := strings.ToLower(string(postBody))

	// Check for lockout
	if postResp.StatusCode == http.StatusTooManyRequests ||
		strings.Contains(postBodyLower, "too many") ||
		strings.Contains(postBodyLower, "account locked") ||
		strings.Contains(postBodyLower, "locked out") {
		return "blocked"
	}

	// Heuristic: successful login usually redirects or removes login form
	isSuccess := false
	if postResp.StatusCode == http.StatusFound || postResp.StatusCode == http.StatusMovedPermanently {
		location := postResp.Header.Get("Location")
		// If redirected away from login page, likely successful
		if location != "" && !strings.Contains(strings.ToLower(location), "login") && !strings.Contains(strings.ToLower(location), "error") {
			isSuccess = true
		}
	}

	// Check for failure indicators
	failureIndicators := []string{"invalid", "incorrect", "wrong password", "bad credentials", "authentication failed", "login failed"}
	hasFailureIndicator := false
	for _, indicator := range failureIndicators {
		if strings.Contains(postBodyLower, indicator) {
			hasFailureIndicator = true
			break
		}
	}

	if isSuccess && !hasFailureIndicator {
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("brute-default-cred-%s", username),
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Default Credentials Accepted: %s/%s", username, password),
			Description:  fmt.Sprintf("The application accepted the default credential pair %q/%q. This allows unauthorized access.", username, password),
			Severity:     scanner.SeverityCritical,
			Confidence:   scanner.ConfidenceSuspected,
			Endpoint:     loginURL,
			Evidence:     fmt.Sprintf("POST to %s with %s:%s received success response", formAction, username, password),
			CVSSScore:    9.8,
			OWASPMapping: "A07:2021 – Identification and Authentication Failures",
			Remediation:  "Change all default credentials immediately. Enforce strong password policies. Implement MFA. Limit login attempts.",
			VulnCode:     "# Application accepts default admin/admin credentials",
			SecureCode:   "# Enforce strong passwords, disable default accounts, implement MFA",
			References: []string{
				"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
				"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
			},
			DiscoveredAt: time.Now(),
		}
		return "success"
	}

	return "failed"
}

func findLoginEndpoint(client *http.Client, baseURL string, httpCfg utils.HTTPConfig, cfg scanner.ScanConfig) string {
	for _, path := range loginPaths {
		testURL := baseURL + path
		resp, err := utils.DoRequest(client, http.MethodGet, testURL, nil, httpCfg)
		if err != nil {
			continue
		}
		utils.SafeClose(resp.Body)
		if resp.StatusCode == http.StatusOK {
			return testURL
		}
	}
	return ""
}

func extractFormAction(body, defaultURL string) string {
	bodyLower := strings.ToLower(body)
	actionIdx := strings.Index(bodyLower, "action=")
	if actionIdx < 0 {
		return defaultURL
	}
	chunk := body[actionIdx+7:]
	quote := string(chunk[0])
	end := strings.Index(chunk[1:], quote)
	if end < 0 {
		return defaultURL
	}
	action := chunk[1 : end+1]
	if strings.HasPrefix(action, "http") {
		return action
	}
	base := defaultURL
	if idx := strings.Index(base, "?"); idx >= 0 {
		base = base[:idx]
	}
	if strings.HasSuffix(base, "/") {
		return base + strings.TrimPrefix(action, "/")
	}
	if strings.HasPrefix(action, "/") {
		// Absolute path from root
		u, err := url.Parse(base)
		if err != nil {
			return defaultURL
		}
		u.Path = action
		return u.String()
	}
	return base + "/" + action
}

func guessUsernameField(body string) string {
	bodyLower := strings.ToLower(body)
	fields := []string{"username", "email", "login", "user", "name", "userid"}
	for _, f := range fields {
		if strings.Contains(bodyLower, "name=\""+f+"\"") || strings.Contains(bodyLower, "name='"+f+"'") {
			return f
		}
	}
	return "username"
}

func guessPasswordField(body string) string {
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "name=\"passwd\"") {
		return "passwd"
	}
	if strings.Contains(bodyLower, "name=\"pass\"") {
		return "pass"
	}
	return "password"
}

func extractCSRFToken(body string) string {
	// Look for common CSRF patterns
	patterns := []string{
		"csrf_token\" value=\"",
		"_token\" value=\"",
		"csrf\" value=\"",
		"authenticity_token\" value=\"",
	}
	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		idx := strings.Index(bodyLower, pattern)
		if idx >= 0 {
			// Get the value
			start := idx + len(pattern)
			end := strings.Index(body[start:], "\"")
			if end > 0 {
				return body[start : start+end]
			}
		}
	}
	return ""
}

func guessCSRFField(body string) string {
	bodyLower := strings.ToLower(body)
	csrfFields := []string{"csrf_token", "_token", "csrf", "authenticity_token", "__requestverificationtoken"}
	for _, f := range csrfFields {
		if strings.Contains(bodyLower, "name=\""+f+"\"") {
			return f
		}
	}
	return "_token"
}
