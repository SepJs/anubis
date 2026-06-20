package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/SepJs/anubis/pkg/delay"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "DNS" }
func (m *Module) Description() string      { return "DNS enumeration and subdomain discovery" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }

// commonSubdomains to probe
var commonSubdomains = []string{
	"www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "backend",
	"api", "dev", "development", "staging", "stage", "test", "uat", "qa",
	"beta", "demo", "cdn", "static", "assets", "media", "img", "images",
	"portal", "vpn", "remote", "ssh", "git", "gitlab", "github", "jira",
	"confluence", "jenkins", "ci", "build", "deploy", "docker", "kubernetes",
	"k8s", "grafana", "prometheus", "kibana", "elastic", "mongo", "redis",
	"db", "database", "mysql", "postgres", "sql", "backup", "files",
	"upload", "uploads", "shop", "store", "blog", "forum", "support",
	"help", "docs", "documentation", "wiki", "internal", "intranet", "corp",
	"ns1", "ns2", "mx", "mx1", "mx2", "smtp1", "smtp2",
}

// level3 extra subdomains for deep scan
var deepSubdomains = []string{
	"app", "apps", "application", "web", "new", "old", "legacy", "v1", "v2", "v3",
	"preview", "pre", "preprod", "prod", "production", "live", "sandbox",
	"monitor", "monitoring", "logs", "logging", "metrics", "status", "health",
	"auth", "login", "sso", "oauth", "openid", "accounts", "account",
	"user", "users", "customer", "clients", "partner", "partners",
	"payment", "pay", "checkout", "billing", "invoice", "finance",
	"hr", "careers", "jobs", "recruitment",
	"ww", "www2", "www3", "old-www", "secure", "ssl",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	host, err := utils.ExtractHost(cfg.Target)
	if err != nil {
		return fmt.Errorf("dns: extract host: %w", err)
	}

	// Strip www. to get root domain
	domain := host
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}

	utils.LogDebug(cfg.Verbose, "dns: enumerating DNS records and subdomains for %s", domain)

	// Run base DNS record lookups
	checkBaseRecords(domain, findings, m.Name())

	// Subdomain enumeration
	subdomains := buildSubdomainList(cfg.Level)
	utils.LogDebug(cfg.Verbose, "dns: probing %d subdomains", len(subdomains))

	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Shared limiter across goroutines — same reasoning as portscan.go: this
	// loop fans out to cfg.Threads concurrent lookups, so per-goroutine
	// limiters would multiply the effective rate. Note this module does NOT
	// use cfg.AdaptiveDelay: net.LookupHost talks to the OS resolver, not an
	// HTTP server, so there's no status code for RecordStatusCode to react
	// to. Fixed/exponential/linear/jitter strategy still applies (it only
	// needs a base delay), just not the adaptive feedback loop.
	limiter := delay.FromConfig(cfg.RateLimit/4, cfg.DelayStrategy, cfg.MaxDelayMs)
	var limiterMu sync.Mutex

	for _, sub := range subdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if cfg.RateLimit > 0 {
				limiterMu.Lock()
				limiter.Wait()
				limiterMu.Unlock()
			}

			fqdn := s + "." + domain
			addrs, err := net.LookupHost(fqdn)
			if err == nil && len(addrs) > 0 {
				severity := scanner.SeverityInfo
				description := fmt.Sprintf("Subdomain %s resolves to %s", fqdn, strings.Join(addrs, ", "))

				// Flag potentially sensitive subdomains
				sensitiveTerms := []string{"admin", "backend", "dev", "staging", "test", "internal", "vpn", "db", "database", "backup", "jenkins", "kibana", "grafana", "mongo", "redis", "elastic"}
				for _, term := range sensitiveTerms {
					if strings.Contains(s, term) {
						severity = scanner.SeverityMedium
						description = fmt.Sprintf("Sensitive-named subdomain %s resolves to %s — verify it is intentionally internet-accessible", fqdn, strings.Join(addrs, ", "))
						break
					}
				}

				findings <- scanner.Finding{
					ID:           fmt.Sprintf("dns-subdomain-%s", fqdn),
					Module:       m.Name(),
					Type:         scanner.FindingInformational,
					Title:        fmt.Sprintf("Subdomain discovered: %s", fqdn),
					Description:  description,
					Severity:     severity,
					Confidence:   scanner.ConfidenceConfirmed,
					Endpoint:     fqdn,
					Metadata:     map[string]string{"addresses": strings.Join(addrs, ", "), "subdomain": s},
					Remediation:  remediation(s),
					DiscoveredAt: time.Now(),
				}
			}
		}(sub)
	}

	wg.Wait()
	return nil
}

func checkBaseRecords(domain string, findings chan<- scanner.Finding, module string) {
	// MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			findings <- scanner.Finding{
				ID:           fmt.Sprintf("dns-mx-%s", mx.Host),
				Module:       module,
				Type:         scanner.FindingInformational,
				Title:        fmt.Sprintf("MX Record: %s (priority %d)", mx.Host, mx.Pref),
				Description:  fmt.Sprintf("Mail exchange record for %s: %s", domain, mx.Host),
				Severity:     scanner.SeverityInfo,
				Confidence:   scanner.ConfidenceConfirmed,
				Endpoint:     domain,
				DiscoveredAt: time.Now(),
			}
		}
	}

	// NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		nsHosts := make([]string, 0, len(nsRecords))
		for _, ns := range nsRecords {
			nsHosts = append(nsHosts, ns.Host)
		}
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("dns-ns-%s", domain),
			Module:       module,
			Type:         scanner.FindingInformational,
			Title:        fmt.Sprintf("Name Servers: %s", strings.Join(nsHosts, ", ")),
			Description:  fmt.Sprintf("Authoritative name servers for %s", domain),
			Severity:     scanner.SeverityInfo,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     domain,
			DiscoveredAt: time.Now(),
		}
	}

	// TXT records — often leak cloud service configurations and SPF
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			severity := scanner.SeverityInfo
			description := fmt.Sprintf("TXT record: %s", txt)

			// Flag interesting TXT records
			txtLower := strings.ToLower(txt)
			if strings.Contains(txtLower, "v=spf1") {
				if strings.Contains(txtLower, "+all") {
					severity = scanner.SeverityHigh
					description = fmt.Sprintf("Permissive SPF record (+all) — any server can spoof email from this domain: %s", txt)
				}
			}
			if strings.Contains(txtLower, "aws") || strings.Contains(txtLower, "google") || strings.Contains(txtLower, "azure") {
				description = fmt.Sprintf("Cloud service verification TXT record: %s", txt)
			}

			findings <- scanner.Finding{
				ID:           fmt.Sprintf("dns-txt-%s", txt[:min(20, len(txt))]),
				Module:       module,
				Type:         scanner.FindingInformational,
				Title:        "TXT Record Found",
				Description:  description,
				Severity:     severity,
				Confidence:   scanner.ConfidenceConfirmed,
				Endpoint:     domain,
				Evidence:     txt,
				DiscoveredAt: time.Now(),
			}
		}
	}

	// Check for zone transfer (AXFR) — common misconfiguration
	checkZoneTransfer(domain, findings, module)
}

func checkZoneTransfer(domain string, findings chan<- scanner.Finding, module string) {
	// Attempt AXFR to see if zone transfers are allowed (safe check, no actual exploitation)
	// We just check if the connection is accepted — actual zone transfer parsing would need dns library
	nsRecords, err := net.LookupNS(domain)
	if err != nil || len(nsRecords) == 0 {
		return
	}

	for _, ns := range nsRecords {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(strings.TrimSuffix(ns.Host, "."), "53"), 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// If we can connect on TCP port 53, zone transfers may be possible
		// Real zone transfer attempt would need raw DNS protocol implementation
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("dns-axfr-possible-%s", ns.Host),
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        fmt.Sprintf("DNS Zone Transfer May Be Possible: %s", ns.Host),
			Description:  fmt.Sprintf("Name server %s accepts TCP connections on port 53, which may allow DNS zone transfers (AXFR). This can expose all DNS records.", ns.Host),
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceSuspected,
			Endpoint:     domain,
			Remediation:  "Restrict zone transfers to authorized secondary name servers only. In BIND: allow-transfer { trusted_secondary_ip; };",
			OWASPMapping: "A05:2021 – Security Misconfiguration",
			DiscoveredAt: time.Now(),
		}
		break // one check is enough
	}
}

func buildSubdomainList(level scanner.ScanLevel) []string {
	subs := make([]string, len(commonSubdomains))
	copy(subs, commonSubdomains)
	if level >= scanner.Level3 {
		subs = append(subs, deepSubdomains...)
	}
	return subs
}

func remediation(sub string) string {
	sensitiveTerms := map[string]string{
		"admin":    "Restrict admin subdomains to internal network access only. Use VPN for remote admin access.",
		"dev":      "Development environments should not be publicly accessible. Use firewall rules or VPN.",
		"staging":  "Staging environments should not be publicly accessible. Protect with HTTP authentication at minimum.",
		"db":       "Database services should never be internet-accessible. Bind to localhost or private network only.",
		"jenkins":  "CI/CD systems should be behind VPN or firewall, not internet-accessible.",
		"grafana":  "Monitoring dashboards should be behind VPN or require strong authentication.",
		"kibana":   "Kibana should be behind authentication and not directly internet-accessible.",
	}
	for term, rem := range sensitiveTerms {
		if strings.Contains(sub, term) {
			return rem
		}
	}
	return "Verify this subdomain is intentionally internet-accessible and properly secured."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
