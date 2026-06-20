package fingerprint

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "FINGERPRINT" }
func (m *Module) Description() string      { return "Server, OS, CMS, and framework fingerprinting" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level3 }

// FingerResult holds detected technology info
type FingerResult struct {
	Server    string
	OS        string
	CMS       string
	Framework string
	Language  string
	Extras    []string
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	httpCfg.RateLimit = cfg.RateLimit

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("fingerprint: build client: %w", err)
	}

	target := utils.NormalizeTarget(cfg.Target)

	// Fetch main page
	resp, err := utils.DoRequest(client, http.MethodGet, target, nil, httpCfg)
	if err != nil {
		return fmt.Errorf("fingerprint: request failed: %w", err)
	}
	defer utils.SafeClose(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return fmt.Errorf("fingerprint: read body: %w", err)
	}

	result := &FingerResult{}
	analyzeHeaders(resp.Header, result)
	analyzeBody(string(body), result)
	analyzeCMSPaths(client, target, httpCfg, result)

	// Emit findings
	emitFindings(result, target, m.Name(), findings)

	return nil
}

func analyzeHeaders(headers http.Header, result *FingerResult) {
	// Server header
	server := headers.Get("Server")
	if server != "" {
		result.Server = server

		// OS hints from server header
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "ubuntu") || strings.Contains(serverLower, "debian") || strings.Contains(serverLower, "centos") || strings.Contains(serverLower, "red hat") {
			result.OS = extractOSFromServer(server)
		}
		if strings.Contains(serverLower, "win") || strings.Contains(serverLower, "iis") {
			result.OS = "Windows"
		}
	}

	// X-Powered-By
	powered := headers.Get("X-Powered-By")
	if powered != "" {
		powered_lower := strings.ToLower(powered)
		if strings.Contains(powered_lower, "php") {
			result.Language = powered
		}
		if strings.Contains(powered_lower, "asp.net") {
			result.Framework = powered
			result.OS = "Windows"
		}
		if strings.Contains(powered_lower, "express") {
			result.Framework = "Express.js (Node.js)"
		}
	}

	// Cookie hints
	setCookie := headers.Get("Set-Cookie")
	if setCookie != "" {
		cookieLower := strings.ToLower(setCookie)
		if strings.Contains(cookieLower, "phpsessid") {
			result.Language = mergeString(result.Language, "PHP")
		}
		if strings.Contains(cookieLower, "asp.net_sessionid") {
			result.Framework = mergeString(result.Framework, "ASP.NET")
		}
		if strings.Contains(cookieLower, "jsessionid") {
			result.Language = mergeString(result.Language, "Java")
		}
		if strings.Contains(cookieLower, "laravel_session") {
			result.Framework = "Laravel (PHP)"
		}
		if strings.Contains(cookieLower, "django") {
			result.Framework = "Django (Python)"
		}
	}

	// Via header
	via := headers.Get("Via")
	if via != "" {
		result.Extras = append(result.Extras, "Proxy/CDN detected: "+via)
	}

	// CF-Ray header
	if headers.Get("CF-Ray") != "" {
		result.Extras = append(result.Extras, "Cloudflare CDN/WAF detected")
	}

	// X-Cache header
	if headers.Get("X-Cache") != "" {
		result.Extras = append(result.Extras, "Caching layer detected: "+headers.Get("X-Cache"))
	}
}

func analyzeBody(body string, result *FingerResult) {
	bodyLower := strings.ToLower(body)

	// CMS detection
	cmsSignatures := map[string]string{
		"wp-content/":                  "WordPress",
		"wp-includes/":                 "WordPress",
		"generator\" content=\"wordpress": "WordPress",
		"drupal.settings":              "Drupal",
		"/sites/default/files/":        "Drupal",
		"joomla":                       "Joomla",
		"/components/com_":             "Joomla",
		"typo3":                        "TYPO3",
		"magento":                      "Magento",
		"mage/":                        "Magento",
		"/mageworx/":                   "Magento",
		"shopify":                      "Shopify",
		"cdn.shopify.com":              "Shopify",
		"wix.com":                      "Wix",
		"squarespace":                  "Squarespace",
	}

	for signature, cms := range cmsSignatures {
		if strings.Contains(bodyLower, signature) {
			result.CMS = cms
			break
		}
	}

	// Framework detection from body hints
	frameworkSignatures := map[string]string{
		"laravel":          "Laravel",
		"__laravel":        "Laravel",
		"data-reactroot":   "React",
		"data-react-":      "React",
		"ng-version":       "Angular",
		"__nuxt":           "Nuxt.js (Vue)",
		"__next":           "Next.js (React)",
		"svelte":           "Svelte",
		"x-powered-by: express": "Express.js",
		"flask":            "Flask (Python)",
		"django":           "Django (Python)",
		"rails":            "Ruby on Rails",
		"csrf-token":       "Rails/Laravel (CSRF token detected)",
	}

	for sig, fw := range frameworkSignatures {
		if strings.Contains(bodyLower, sig) {
			result.Framework = mergeString(result.Framework, fw)
			break
		}
	}

	// Language detection
	languageSignatures := map[string]string{
		".php":    "PHP",
		".asp":    "ASP (Classic)",
		".aspx":   "ASP.NET",
		".jsp":    "Java",
		".do":     "Java Struts",
		".rb":     "Ruby",
		".py":     "Python",
		".pl":     "Perl",
		".cfm":    "ColdFusion",
	}

	for sig, lang := range languageSignatures {
		if strings.Contains(bodyLower, sig) {
			result.Language = mergeString(result.Language, lang)
		}
	}

	// Generator meta tag
	if idx := strings.Index(bodyLower, "generator"); idx >= 0 && idx < len(bodyLower)-50 {
		chunk := body[idx : min(idx+100, len(body))]
		result.Extras = append(result.Extras, "Generator meta: "+strings.TrimSpace(chunk))
	}
}

// analyzeCMSPaths probes well-known CMS paths to confirm detection
func analyzeCMSPaths(client *http.Client, target string, httpCfg utils.HTTPConfig, result *FingerResult) {
	cmsPaths := map[string]string{
		"/wp-login.php":         "WordPress",
		"/wp-admin/":            "WordPress",
		"/administrator/":       "Joomla",
		"/index.php?option=com_": "Joomla",
		"/user/login":           "Drupal",
		"/sites/default/":       "Drupal",
		"/typo3/":               "TYPO3",
	}

	base := strings.TrimRight(target, "/")
	for path, cms := range cmsPaths {
		if result.CMS != "" {
			break // already identified
		}
		resp, err := utils.DoRequest(client, http.MethodGet, base+path, nil, httpCfg)
		if err != nil {
			continue
		}
		utils.SafeClose(resp.Body)
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			result.CMS = cms
		}
	}
}

func emitFindings(result *FingerResult, target, module string, findings chan<- scanner.Finding) {
	metadata := map[string]string{}

	if result.Server != "" {
		metadata["server"] = result.Server
	}
	if result.OS != "" {
		metadata["os"] = result.OS
	}
	if result.CMS != "" {
		metadata["cms"] = result.CMS
	}
	if result.Framework != "" {
		metadata["framework"] = result.Framework
	}
	if result.Language != "" {
		metadata["language"] = result.Language
	}

	summary := buildSummary(result)

	if summary != "" {
		findings <- scanner.Finding{
			ID:           "fingerprint-tech-stack",
			Module:       module,
			Type:         scanner.FindingInformational,
			Title:        "Technology Stack Fingerprinted",
			Description:  summary,
			Severity:     scanner.SeverityInfo,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     target,
			Metadata:     metadata,
			Remediation:  "Remove or obfuscate version-revealing headers (Server, X-Powered-By). This information aids attackers in finding applicable exploits.",
			DiscoveredAt: time.Now(),
		}
	}

	for _, extra := range result.Extras {
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("fingerprint-extra-%s", strings.ReplaceAll(extra[:min(20, len(extra))], " ", "-")),
			Module:       module,
			Type:         scanner.FindingInformational,
			Title:        "Infrastructure Detail Detected",
			Description:  extra,
			Severity:     scanner.SeverityInfo,
			Confidence:   scanner.ConfidenceSuspected,
			Endpoint:     target,
			DiscoveredAt: time.Now(),
		}
	}

	// Check for outdated CMS versions (heuristic)
	if result.CMS == "WordPress" {
		findings <- scanner.Finding{
			ID:           "fingerprint-cms-wordpress",
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        "WordPress CMS Detected",
			Description:  "WordPress installation detected. Ensure WordPress core, themes, and plugins are up to date. WordPress is a frequent target for automated exploitation.",
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     target,
			OWASPMapping: "A06:2021 – Vulnerable and Outdated Components",
			Remediation:  "Keep WordPress core, themes, and plugins updated. Disable XML-RPC if not needed. Use a security plugin (Wordfence, etc.).",
			References:   []string{"https://wordpress.org/support/article/hardening-wordpress/"},
			DiscoveredAt: time.Now(),
		}
	}
}

func buildSummary(result *FingerResult) string {
	var parts []string
	if result.Server != "" {
		parts = append(parts, "Web server: "+result.Server)
	}
	if result.OS != "" {
		parts = append(parts, "OS: "+result.OS)
	}
	if result.CMS != "" {
		parts = append(parts, "CMS: "+result.CMS)
	}
	if result.Framework != "" {
		parts = append(parts, "Framework: "+result.Framework)
	}
	if result.Language != "" {
		parts = append(parts, "Language: "+result.Language)
	}
	return strings.Join(parts, " | ")
}

func extractOSFromServer(server string) string {
	lower := strings.ToLower(server)
	if strings.Contains(lower, "ubuntu") {
		return "Linux (Ubuntu)"
	}
	if strings.Contains(lower, "debian") {
		return "Linux (Debian)"
	}
	if strings.Contains(lower, "centos") {
		return "Linux (CentOS)"
	}
	if strings.Contains(lower, "red hat") || strings.Contains(lower, "rhel") {
		return "Linux (RHEL)"
	}
	if strings.Contains(lower, "fedora") {
		return "Linux (Fedora)"
	}
	return "Linux"
}

func mergeString(existing, new string) string {
	if existing == "" {
		return new
	}
	if strings.Contains(existing, new) {
		return existing
	}
	return existing + " / " + new
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
