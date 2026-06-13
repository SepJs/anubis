package headers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "HEADERS" }
func (m *Module) Description() string      { return "HTTP security headers validation" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

type headerCheck struct {
	name        string
	required    bool
	severity    scanner.Severity
	description string
	remediation string
	vulnCode    string
	secureCode  string
	owasp       string
	validator   func(value string) (ok bool, note string)
}

var checks = []headerCheck{
	{
		name:        "Content-Security-Policy",
		required:    true,
		severity:    scanner.SeverityHigh,
		description: "Content-Security-Policy (CSP) header is missing. This allows attackers to inject and execute malicious scripts (XSS).",
		remediation: "Add a strict CSP header. Start with a restrictive policy and relax as needed.",
		vulnCode:    "# Missing CSP header — no protection against XSS",
		secureCode:  "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
		owasp:       "A03:2021 – Injection",
	},
	{
		name:        "X-Content-Type-Options",
		required:    true,
		severity:    scanner.SeverityMedium,
		description: "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, potentially executing non-script resources as scripts.",
		remediation: "Add: X-Content-Type-Options: nosniff",
		vulnCode:    "# Missing — browser may MIME-sniff",
		secureCode:  "X-Content-Type-Options: nosniff",
		owasp:       "A05:2021 – Security Misconfiguration",
	},
	{
		name:        "Strict-Transport-Security",
		required:    true,
		severity:    scanner.SeverityMedium,
		description: "HTTP Strict Transport Security (HSTS) header is missing. Users can be downgraded to HTTP connections.",
		remediation: "Add HSTS with a long max-age. Consider including subdomains and preload.",
		vulnCode:    "# Missing HSTS — HTTP downgrade possible",
		secureCode:  "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		owasp:       "A02:2021 – Cryptographic Failures",
		validator: func(value string) (bool, string) {
			if !strings.Contains(value, "max-age") {
				return false, "HSTS header is present but missing max-age directive"
			}
			return true, ""
		},
	},
	{
		name:        "Referrer-Policy",
		required:    false,
		severity:    scanner.SeverityLow,
		description: "Referrer-Policy header is missing. The browser may leak the full URL in the Referer header to third parties.",
		remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
		secureCode:  "Referrer-Policy: strict-origin-when-cross-origin",
		owasp:       "A05:2021 – Security Misconfiguration",
	},
	{
		name:        "X-Frame-Options",
		required:    true,
		severity:    scanner.SeverityMedium,
		description: "X-Frame-Options header is missing. The page can be embedded in an iframe, enabling clickjacking attacks.",
		remediation: "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframe embedding is needed on same domain)",
		vulnCode:    "# Missing — clickjacking possible",
		secureCode:  "X-Frame-Options: DENY",
		owasp:       "A05:2021 – Security Misconfiguration",
	},
	{
		name:        "Permissions-Policy",
		required:    false,
		severity:    scanner.SeverityLow,
		description: "Permissions-Policy header is missing. Browser features (camera, microphone, geolocation) are not explicitly restricted.",
		remediation: "Add a Permissions-Policy header restricting unused browser features.",
		secureCode:  "Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()",
		owasp:       "A05:2021 – Security Misconfiguration",
	},
	{
		name:        "X-XSS-Protection",
		required:    false,
		severity:    scanner.SeverityLow,
		description: "X-XSS-Protection header is missing. Modern browsers have deprecated this, but older browsers benefit from it.",
		remediation: "Add: X-XSS-Protection: 1; mode=block (or 0 to disable broken IE implementation)",
		secureCode:  "X-XSS-Protection: 1; mode=block",
		owasp:       "A03:2021 – Injection",
	},
}

// dangerousHeaders are headers that should NOT be present
var dangerousHeaders = []struct {
	name        string
	description string
	remediation string
	severity    scanner.Severity
}{
	{
		name:        "Server",
		description: "Server header reveals the web server version, aiding attackers in targeting known vulnerabilities.",
		remediation: "Remove or obfuscate the Server header in your web server configuration.",
		severity:    scanner.SeverityLow,
	},
	{
		name:        "X-Powered-By",
		description: "X-Powered-By header reveals the backend technology stack (e.g., PHP/5.6), aiding attackers.",
		remediation: "Remove the X-Powered-By header (e.g., header_remove('X-Powered-By') in PHP).",
		severity:    scanner.SeverityLow,
	},
	{
		name:        "X-AspNet-Version",
		description: "X-AspNet-Version header exposes the ASP.NET framework version.",
		remediation: "Set <httpRuntime enableVersionHeader='false' /> in Web.config.",
		severity:    scanner.SeverityLow,
	},
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	httpCfg.RateLimit = cfg.RateLimit

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("headers: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	resp, err := utils.DoRequest(client, http.MethodGet, target, nil, httpCfg)
	if err != nil {
		return fmt.Errorf("headers: request failed: %w", err)
	}
	defer utils.SafeClose(resp.Body)

	utils.LogDebug(cfg.Verbose, "headers: analyzing response headers for %s", target)

	// Check required/recommended security headers
	for _, check := range checks {
		value := resp.Header.Get(check.name)
		if value == "" {
			sev := check.severity
			if !check.required {
				// Non-required missing headers are lower severity
				if sev == scanner.SeverityHigh {
					sev = scanner.SeverityMedium
				}
			}
			findings <- scanner.Finding{
				ID:           fmt.Sprintf("header-missing-%s", strings.ToLower(strings.ReplaceAll(check.name, "-", ""))),
				Module:       m.Name(),
				Type:         scanner.FindingMisconfiguration,
				Title:        fmt.Sprintf("Missing Security Header: %s", check.name),
				Description:  check.description,
				Severity:     sev,
				Confidence:   scanner.ConfidenceConfirmed,
				Endpoint:     target,
				Remediation:  check.remediation,
				VulnCode:     check.vulnCode,
				SecureCode:   check.secureCode,
				OWASPMapping: check.owasp,
				DiscoveredAt: time.Now(),
			}
		} else if check.validator != nil {
			ok, note := check.validator(value)
			if !ok {
				findings <- scanner.Finding{
					ID:           fmt.Sprintf("header-misconfigured-%s", strings.ToLower(strings.ReplaceAll(check.name, "-", ""))),
					Module:       m.Name(),
					Type:         scanner.FindingMisconfiguration,
					Title:        fmt.Sprintf("Misconfigured Header: %s", check.name),
					Description:  note,
					Severity:     scanner.SeverityLow,
					Confidence:   scanner.ConfidenceConfirmed,
					Endpoint:     target,
					Remediation:  check.remediation,
					SecureCode:   check.secureCode,
					OWASPMapping: check.owasp,
					DiscoveredAt: time.Now(),
				}
			}
		}
	}

	// Check for dangerous/verbose headers
	for _, bad := range dangerousHeaders {
		value := resp.Header.Get(bad.name)
		if value != "" {
			findings <- scanner.Finding{
				ID:           fmt.Sprintf("header-exposed-%s", strings.ToLower(strings.ReplaceAll(bad.name, "-", ""))),
				Module:       m.Name(),
				Type:         scanner.FindingInformational,
				Title:        fmt.Sprintf("Information Disclosure: %s: %s", bad.name, value),
				Description:  bad.description,
				Severity:     bad.severity,
				Confidence:   scanner.ConfidenceConfirmed,
				Endpoint:     target,
				Evidence:     fmt.Sprintf("%s: %s", bad.name, value),
				Remediation:  bad.remediation,
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}
