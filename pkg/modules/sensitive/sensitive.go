package sensitive

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/innervoid/anubis/pkg/delay"
	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "SENSITIVE_FILES" }
func (m *Module) Description() string      { return "Sensitive file and information discovery" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

type sensitiveFile struct {
	path        string
	description string
	severity    scanner.Severity
	remediation string
	level       scanner.ScanLevel // minimum level to check this path
}

var filePaths = []sensitiveFile{
	// Level 1 — basic
	{"/robots.txt", "robots.txt exposes site structure and potentially hidden paths", scanner.SeverityInfo, "Review robots.txt to ensure sensitive paths are not disclosed. Consider removing disallow entries that hint at admin paths.", scanner.Level1},
	{"/.env", ".env file is publicly accessible — may contain credentials, API keys, and database passwords", scanner.SeverityCritical, "Deny access to .env files in your web server config. Never store .env files in the web root.", scanner.Level1},
	{"/.env.local", ".env.local file accessible", scanner.SeverityCritical, "Deny access to all .env* files at the web server level.", scanner.Level1},
	{"/.env.production", ".env.production file accessible", scanner.SeverityCritical, "Deny access to all .env* files at the web server level.", scanner.Level1},
	{"/backup.zip", "Backup archive accessible publicly — may contain full source code", scanner.SeverityCritical, "Remove backup files from the web root. Store backups in a non-web-accessible location.", scanner.Level1},
	{"/backup.tar.gz", "Backup archive accessible publicly", scanner.SeverityCritical, "Remove all archive files from the web root.", scanner.Level1},
	{"/www.zip", "Site backup archive accessible", scanner.SeverityCritical, "Remove all archive files from the web root.", scanner.Level1},
	{"/.git/config", "Git repository config accessible — exposes repository structure and potentially credentials", scanner.SeverityCritical, "Block access to .git directory: deny access to /.git/ in web server config.", scanner.Level1},
	{"/.git/HEAD", "Git HEAD reference accessible", scanner.SeverityHigh, "Block access to .git directory in web server configuration.", scanner.Level1},
	{"/wp-config.php.bak", "WordPress config backup accessible", scanner.SeverityCritical, "Remove backup files of sensitive config. Never leave .bak files in the web root.", scanner.Level1},
	{"/config.php", "PHP config file accessible", scanner.SeverityHigh, "Restrict access to config files or move them outside the web root.", scanner.Level1},
	{"/phpinfo.php", "phpinfo() output accessible — reveals full PHP configuration, environment variables, and loaded modules", scanner.SeverityHigh, "Remove phpinfo.php from production. This file aids attacker reconnaissance.", scanner.Level1},

	// Level 2 — deeper
	{"/admin", "Admin panel accessible", scanner.SeverityMedium, "Restrict admin panel access by IP, add authentication, and consider moving to a non-obvious path.", scanner.Level2},
	{"/admin/", "Admin panel accessible", scanner.SeverityMedium, "Restrict admin panel access.", scanner.Level2},
	{"/administrator", "Administrator panel accessible", scanner.SeverityMedium, "Restrict admin panel access by IP and ensure strong authentication.", scanner.Level2},
	{"/wp-admin/", "WordPress admin panel accessible", scanner.SeverityMedium, "Restrict /wp-admin/ by IP or with additional authentication layers.", scanner.Level2},
	{"/wp-login.php", "WordPress login page accessible", scanner.SeverityLow, "Consider IP-restricting the WordPress login page or adding 2FA.", scanner.Level2},
	{"/phpmyadmin", "phpMyAdmin panel accessible — database management exposed", scanner.SeverityCritical, "Restrict phpMyAdmin to localhost or internal network only.", scanner.Level2},
	{"/phpmyadmin/", "phpMyAdmin panel accessible", scanner.SeverityCritical, "Restrict phpMyAdmin access to trusted IPs only.", scanner.Level2},
	{"/server-status", "Apache server-status page accessible — reveals active requests, worker status, and internal IPs", scanner.SeverityHigh, "Restrict /server-status to localhost: Allow from 127.0.0.1", scanner.Level2},
	{"/server-info", "Apache server-info page accessible — reveals full module and configuration details", scanner.SeverityHigh, "Restrict /server-info to localhost.", scanner.Level2},
	{"/.DS_Store", ".DS_Store file accessible — reveals directory structure on macOS-served sites", scanner.SeverityMedium, "Block access to .DS_Store files and remove them from the repository.", scanner.Level2},
	{"/error_log", "PHP/Apache error log accessible — may reveal internal paths and stack traces", scanner.SeverityHigh, "Restrict access to log files. Store logs outside the web root.", scanner.Level2},
	{"/debug.log", "Debug log accessible", scanner.SeverityMedium, "Remove debug logs from the web root.", scanner.Level2},
	{"/npm-debug.log", "npm debug log accessible — may reveal Node.js internals", scanner.SeverityMedium, "Remove log files from the web root.", scanner.Level2},

	// Level 3 — aggressive discovery
	{"/config/database.yml", "Rails database config accessible — may contain credentials", scanner.SeverityCritical, "Restrict access to config files outside the web root.", scanner.Level3},
	{"/config/secrets.yml", "Rails secrets config accessible", scanner.SeverityCritical, "Move secrets.yml outside the web root.", scanner.Level3},
	{"/config.yml", "YAML config accessible", scanner.SeverityHigh, "Restrict access to configuration files.", scanner.Level3},
	{"/settings.py", "Django settings file accessible", scanner.SeverityCritical, "Ensure Django settings are never in the web root. Use WSGI correctly.", scanner.Level3},
	{"/local_settings.py", "Django local settings accessible", scanner.SeverityCritical, "Remove local_settings.py from the web root.", scanner.Level3},
	{"/credentials.json", "Credentials JSON accessible", scanner.SeverityCritical, "Remove credential files from the web root immediately.", scanner.Level3},
	{"/api/swagger.json", "Swagger/OpenAPI spec accessible — reveals all API endpoints", scanner.SeverityMedium, "Restrict Swagger UI and spec to authenticated users or development environments only.", scanner.Level3},
	{"/swagger.json", "Swagger spec accessible", scanner.SeverityMedium, "Restrict API documentation access in production.", scanner.Level3},
	{"/openapi.json", "OpenAPI spec accessible", scanner.SeverityMedium, "Restrict API documentation in production.", scanner.Level3},
	{"/graphql", "GraphQL endpoint accessible — check for introspection", scanner.SeverityMedium, "Disable GraphQL introspection in production.", scanner.Level3},
	{"/.travis.yml", "Travis CI config accessible — may reveal build secrets or pipeline structure", scanner.SeverityLow, "Add .travis.yml to .gitignore if it contains sensitive values.", scanner.Level3},
	{"/.circleci/config.yml", "CircleCI config accessible", scanner.SeverityLow, "Ensure CI configs do not contain hardcoded secrets.", scanner.Level3},
	{"/Dockerfile", "Dockerfile accessible — reveals build process and base images", scanner.SeverityLow, "Restrict access to Dockerfiles in production.", scanner.Level3},
	{"/docker-compose.yml", "docker-compose.yml accessible — may reveal service architecture and credentials", scanner.SeverityMedium, "Do not expose infrastructure config files via the web server.", scanner.Level3},
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	// Pacing is handled entirely by the delay.Limiter below, not by
	// DoRequest's built-in sleep — explicitly zero this out, otherwise
	// DefaultHTTPConfig()'s 100ms default silently stacks with the Limiter's
	// delay on every single request.
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("sensitive: build client: %w", err)
	}

	baseURL := strings.TrimRight(utils.NormalizeTarget(cfg.Target), "/")

	// Respect robots.txt if configured
	disallowed := map[string]bool{}
	if cfg.RespectLimits {
		disallowed = fetchDisallowed(client, baseURL, httpCfg)
	}

	// Filter paths for current level
	var eligible []sensitiveFile
	for _, f := range filePaths {
		if f.level <= cfg.Level {
			eligible = append(eligible, f)
		}
	}

	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// One shared limiter across all goroutines for this module — see the
	// comment in pkg/modules/portscan/portscan.go for why a per-goroutine
	// limiter would silently multiply the effective request rate by cfg.Threads.
	baseRate := cfg.RateLimit / 2 // file probes can run slightly faster than the global default
	limiter := delay.FromConfig(baseRate, cfg.DelayStrategy, cfg.MaxDelayMs)
	var limiterMu sync.Mutex

	for _, file := range eligible {
		if cfg.RespectLimits && disallowed[file.path] {
			utils.LogDebug(cfg.Verbose, "sensitive: skipping %s (disallowed by robots.txt)", file.path)
			continue
		}

		wg.Add(1)
		go func(f sensitiveFile) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			checkFile(client, baseURL, f, httpCfg, cfg, findings, m.Name(), limiter, &limiterMu)
		}(file)
	}

	wg.Wait()
	return nil
}

// checkFile probes a single path. The limiter parameter paces requests; when
// cfg.AdaptiveDelay is set, the observed status code feeds back into the
// limiter's backoff state via RecordStatusCode, so a 429/503 response slows
// down subsequent requests from every goroutine sharing this limiter.
func checkFile(
	client *http.Client,
	baseURL string,
	f sensitiveFile,
	httpCfg utils.HTTPConfig,
	cfg scanner.ScanConfig,
	findings chan<- scanner.Finding,
	module string,
	limiter *delay.Limiter,
	limiterMu *sync.Mutex,
) {
	url := baseURL + f.path

	resp, err := utils.DoRequest(client, http.MethodGet, url, nil, httpCfg)

	// Pace *after* seeing the outcome so adaptive mode has a status code to
	// react to before the next goroutine's request goes out. Holding the
	// lock across Wait() is intentional — it's what makes the rate genuinely
	// shared rather than approximately shared.
	limiterMu.Lock()
	if cfg.AdaptiveDelay && err == nil {
		limiter.RecordStatusCode(resp.StatusCode)
	}
	if cfg.RateLimit > 0 {
		limiter.Wait()
	}
	limiterMu.Unlock()

	if err != nil {
		return
	}
	defer utils.SafeClose(resp.Body)

	// Only flag if actually accessible (200, 403 can also be interesting for admin panels)
	if resp.StatusCode == http.StatusOK {
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("sensitive-%s", strings.ReplaceAll(f.path, "/", "-")),
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Sensitive File Accessible: %s", f.path),
			Description:  f.description,
			Severity:     f.severity,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     url,
			Remediation:  f.remediation,
			OWASPMapping: "A05:2021 – Security Misconfiguration",
			DiscoveredAt: time.Now(),
		}
	} else if resp.StatusCode == http.StatusForbidden && f.severity >= scanner.SeverityHigh {
		// Forbidden still confirms the path exists
		findings <- scanner.Finding{
			ID:           fmt.Sprintf("sensitive-forbidden-%s", strings.ReplaceAll(f.path, "/", "-")),
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        fmt.Sprintf("Sensitive Path Exists (403): %s", f.path),
			Description:  fmt.Sprintf("The path %s returned 403 Forbidden — it exists but is currently protected. Ensure proper access control is maintained.", f.path),
			Severity:     scanner.SeverityLow,
			Confidence:   scanner.ConfidenceSuspected,
			Endpoint:     url,
			Remediation:  f.remediation,
			DiscoveredAt: time.Now(),
		}
	}
}

func fetchDisallowed(client *http.Client, baseURL string, httpCfg utils.HTTPConfig) map[string]bool {
	disallowed := map[string]bool{}
	resp, err := utils.DoRequest(client, http.MethodGet, baseURL+"/robots.txt", nil, httpCfg)
	if err != nil || resp.StatusCode != http.StatusOK {
		return disallowed
	}
	defer utils.SafeClose(resp.Body)

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[9:])
			if path != "" {
				disallowed[path] = true
			}
		}
	}
	return disallowed
}
