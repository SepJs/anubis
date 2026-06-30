// Package headers audits HTTP security response headers.
package headers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

// Module checks HTTP security headers.
type Module struct{}

func New() *Module                         { return &Module{} }
func (m *Module) Name() string             { return "HEADERS" }
func (m *Module) Description() string      { return "HTTP security header audit" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	httpCfg.RateLimit = 0 // single request — no rate limiting needed

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("headers: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)
	resp, err := utils.DoRequest(client, http.MethodGet, target, nil, httpCfg)
	if err != nil {
		return fmt.Errorf("headers: request: %w", err)
	}
	defer utils.SafeClose(resp.Body)

	checkSecurityHeaders(resp.Header, target, cfg, findings, m.Name())
	checkInformationDisclosure(resp.Header, target, findings, m.Name())

	return nil
}

// checkSecurityHeaders validates required and recommended headers.
func checkSecurityHeaders(h http.Header, target string, cfg scanner.ScanConfig, findings chan<- scanner.Finding, module string) {
	// ── Content-Security-Policy ─────────────────────────────────────────
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		findings <- scanner.Finding{
			ID: "header-missing-csp", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: Content-Security-Policy",
			Description:  "No CSP header. Browsers have no instruction on which scripts/resources are trusted — XSS attacks can run freely.",
			Severity:     scanner.SeverityHigh, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target, OWASPMapping: "A05:2021 – Security Misconfiguration",
			Remediation: "Add a restrictive CSP. Start: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
			SecureCode:  "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
			DiscoveredAt: time.Now(),
		}
	} else {
		// CSP present — check for dangerous directives that weaken it.
		cspLower := strings.ToLower(csp)
		if strings.Contains(cspLower, "'unsafe-inline'") {
			findings <- scanner.Finding{
				ID: "header-csp-unsafe-inline", Module: module,
				Type: scanner.FindingWeakness, Title: "Weak CSP: 'unsafe-inline' present",
				Description:  "CSP contains 'unsafe-inline' which defeats XSS protection by allowing inline scripts.",
				Severity:     scanner.SeverityMedium, Confidence: scanner.ConfidenceConfirmed,
				Endpoint: target, Evidence: csp,
				Remediation: "Remove 'unsafe-inline'. Use nonce- or hash-based CSP instead.",
				DiscoveredAt: time.Now(),
			}
		}
		if strings.Contains(cspLower, "'unsafe-eval'") {
			findings <- scanner.Finding{
				ID: "header-csp-unsafe-eval", Module: module,
				Type: scanner.FindingWeakness, Title: "Weak CSP: 'unsafe-eval' present",
				Description:  "CSP allows eval() which enables JS injection attacks even without inline scripts.",
				Severity:     scanner.SeverityMedium, Confidence: scanner.ConfidenceConfirmed,
				Endpoint: target, Evidence: csp,
				Remediation: "Remove 'unsafe-eval'. Rewrite code that relies on eval().",
				DiscoveredAt: time.Now(),
			}
		}
	}

	// ── X-Content-Type-Options ──────────────────────────────────────────
	xcto := h.Get("X-Content-Type-Options")
	if xcto == "" {
		findings <- scanner.Finding{
			ID: "header-missing-xcto", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: X-Content-Type-Options",
			Description:  "Browser may MIME-sniff responses, executing non-script files as scripts.",
			Severity:     scanner.SeverityMedium, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target,
			Remediation: "Add: X-Content-Type-Options: nosniff",
			SecureCode:  "X-Content-Type-Options: nosniff",
			DiscoveredAt: time.Now(),
		}
	}

	// ── Strict-Transport-Security ───────────────────────────────────────
	hsts := h.Get("Strict-Transport-Security")
	if hsts == "" {
		findings <- scanner.Finding{
			ID: "header-missing-hsts", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: Strict-Transport-Security",
			Description:  "No HSTS header. Browsers may allow HTTP connections — enabling downgrade attacks.",
			Severity:     scanner.SeverityMedium, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target, OWASPMapping: "A02:2021 – Cryptographic Failures",
			Remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			SecureCode:  "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			DiscoveredAt: time.Now(),
		}
	} else if !strings.Contains(strings.ToLower(hsts), "max-age") {
		findings <- scanner.Finding{
			ID: "header-hsts-no-maxage", Module: module,
			Type: scanner.FindingWeakness, Title: "HSTS header missing max-age",
			Description:  "HSTS is present but has no max-age directive — browsers will ignore it.",
			Severity:     scanner.SeverityLow, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target, Evidence: hsts,
			Remediation: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
			DiscoveredAt: time.Now(),
		}
	}

	// ── X-Frame-Options ─────────────────────────────────────────────────
	xfo := h.Get("X-Frame-Options")
	if xfo == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		// Only flag if CSP doesn't already cover frame-ancestors
		findings <- scanner.Finding{
			ID: "header-missing-xfo", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: X-Frame-Options",
			Description:  "Page can be embedded in an iframe — clickjacking attacks possible.",
			Severity:     scanner.SeverityMedium, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target,
			Remediation: "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors 'none')",
			SecureCode:  "X-Frame-Options: DENY",
			DiscoveredAt: time.Now(),
		}
	}

	// ── Referrer-Policy ─────────────────────────────────────────────────
	if h.Get("Referrer-Policy") == "" {
		findings <- scanner.Finding{
			ID: "header-missing-referrer-policy", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: Referrer-Policy",
			Description:  "Browser may leak the full URL in Referer header to third-party requests.",
			Severity:     scanner.SeverityLow, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target,
			SecureCode:  "Referrer-Policy: strict-origin-when-cross-origin",
			DiscoveredAt: time.Now(),
		}
	}

	// ── Permissions-Policy ──────────────────────────────────────────────
	if h.Get("Permissions-Policy") == "" {
		findings <- scanner.Finding{
			ID: "header-missing-permissions-policy", Module: module,
			Type: scanner.FindingMisconfiguration, Title: "Missing: Permissions-Policy",
			Description:  "Browser features (camera, microphone, geolocation) are not explicitly restricted.",
			Severity:     scanner.SeverityLow, Confidence: scanner.ConfidenceConfirmed,
			Endpoint: target,
			SecureCode:  "Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()",
			DiscoveredAt: time.Now(),
		}
	}
}

// checkInformationDisclosure flags headers that expose server technology details.
func checkInformationDisclosure(h http.Header, target string, findings chan<- scanner.Finding, module string) {
	sensitive := []struct {
		name, desc, fix string
	}{
		{"Server", "Reveals web server version — aids targeted exploitation.", "Remove or genericise the Server header in web server config."},
		{"X-Powered-By", "Reveals backend technology stack (e.g. PHP/8.1) — aids exploitation.", "Remove header: header_remove('X-Powered-By') in PHP, or config in nginx/apache."},
		{"X-AspNet-Version", "Exposes ASP.NET framework version.", "Set <httpRuntime enableVersionHeader='false'/> in Web.config."},
		{"X-AspNetMvc-Version", "Exposes ASP.NET MVC version.", "Call MvcHandler.DisableMvcResponseHeader = true in Global.asax."},
		{"X-Generator", "Reveals CMS or framework version.", "Configure CMS to suppress generator headers."},
	}

	for _, s := range sensitive {
		val := h.Get(s.name)
		if val == "" {
			continue
		}
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("header-disclosure-%s", strings.ToLower(strings.ReplaceAll(s.name, "-", ""))),
			Module:       module,
			Type:         scanner.FindingInformational,
			Title:        fmt.Sprintf("Info disclosure: %s: %s", s.name, val),
			Description:  s.desc,
			Severity:     scanner.SeverityLow,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     target,
			Evidence:     fmt.Sprintf("%s: %s", s.name, val),
			Remediation:  s.fix,
			DiscoveredAt: time.Now(),
		}
	}
}
