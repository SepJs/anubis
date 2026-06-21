// Package portscan implements TCP port scanning with service banner grabbing.
package portscan

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SepJs/anubis/pkg/delay"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

// Module performs TCP port scanning with optional banner grabbing.
type Module struct{}

func New() *Module                      { return &Module{} }
func (m *Module) Name() string          { return "PORT_SCAN" }
func (m *Module) Description() string   { return "TCP port scan + service banner grabbing" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

// portDef describes a port we're interested in.
type portDef struct {
	port        int
	service     string
	risky       bool
	riskNote    string
	remediation string
	grabBanner  bool // whether to attempt a banner read after connecting
}

// knownPorts lists ports to scan at each level.
// Level 1 = first N, Level 2 adds more, Level 3 adds the rest.
var knownPorts = []portDef{
	// ── Level 1 ─────────────────────────────────────────────
	{21, "FTP", true, "FTP transmits credentials in plaintext", "Disable FTP; use SFTP (SSH) instead.", true},
	{22, "SSH", false, "", "", true},
	{23, "Telnet", true, "Telnet is unencrypted and should be disabled", "Replace with SSH: `systemctl disable telnet`", false},
	{25, "SMTP", false, "", "", false},
	{53, "DNS", false, "", "", false},
	{80, "HTTP", false, "", "", true},
	{110, "POP3", false, "", "", false},
	{143, "IMAP", false, "", "", false},
	{443, "HTTPS", false, "", "", false},
	{445, "SMB", true, "SMB exposed to internet is a serious risk (EternalBlue etc.)", "Block SMB (445/TCP) at the firewall; never expose to internet.", false},
	{993, "IMAPS", false, "", "", false},
	{995, "POP3S", false, "", "", false},
	{3306, "MySQL", true, "MySQL should not be internet-accessible", "Bind to 127.0.0.1; use SSH tunnel for remote access.", false},
	{3389, "RDP", true, "RDP exposed to internet is a high-value attack target", "Place behind VPN; restrict by IP at firewall.", false},
	{5432, "PostgreSQL", true, "PostgreSQL should not be internet-accessible", "Bind to localhost; use SSH tunnel.", false},
	{6379, "Redis", true, "Redis has no auth by default — critical if internet-facing", "Bind to 127.0.0.1; enable AUTH; firewall external access.", false},
	{8080, "HTTP-Alt", false, "", "", true},
	{8443, "HTTPS-Alt", false, "", "", false},
	{27017, "MongoDB", true, "MongoDB without auth + internet = data breach", "Enable auth; bind to localhost; firewall external access.", false},

	// ── Level 2 extras ──────────────────────────────────────
	{69, "TFTP", true, "TFTP is unauthenticated and unencrypted", "Disable TFTP; never expose to internet.", false},
	{389, "LDAP", true, "Unencrypted LDAP exposes directory data", "Use LDAPS (636) instead; block 389 at firewall.", false},
	{636, "LDAPS", false, "", "", false},
	{1433, "MSSQL", true, "MSSQL should not be internet-accessible", "Block at firewall; use VPN for remote DBA access.", false},
	{1521, "Oracle", true, "Oracle DB should not be internet-accessible", "Block at firewall.", false},
	{2049, "NFS", true, "NFS exposed to internet leaks filesystem contents", "Bind NFS to internal network; firewall external access.", false},
	{3000, "Node/Grafana", false, "", "", true},
	{5900, "VNC", true, "VNC should never be internet-accessible", "Disable or bind to localhost; use SSH tunnel instead.", false},
	{5985, "WinRM-HTTP", true, "WinRM exposed to internet", "Block at firewall; use HTTPS variant (5986) over VPN.", false},
	{8000, "HTTP-Dev", false, "", "", true},
	{8001, "HTTP-Dev", false, "", "", false},
	{8888, "Jupyter/HTTP", true, "Jupyter Notebook exposed = remote code execution", "Bind to localhost; add strong auth; never expose to internet.", true},
	{9000, "PHP-FPM/Portainer", false, "", "", false},
	{9200, "Elasticsearch", true, "Elasticsearch without auth = data breach", "Enable security (X-Pack); bind to localhost.", false},
	{9300, "Elasticsearch", false, "", "", false},
	{11211, "Memcached", true, "Memcached has no auth; used in amplification DDoS", "Bind to localhost; block UDP 11211 at firewall.", false},
	{15672, "RabbitMQ Mgmt", true, "RabbitMQ management UI exposed", "Restrict to internal network; change default credentials.", false},
	{27018, "MongoDB", false, "", "", false},

	// ── Level 3 extras ──────────────────────────────────────
	{161, "SNMP", true, "SNMP v1/v2 uses community strings (effectively no auth)", "Upgrade to SNMPv3; block UDP 161 externally.", false},
	{500, "IKE/IPSec", false, "", "", false},
	{2375, "Docker API (HTTP)", true, "Unprotected Docker API = full host compromise", "Never expose Docker API without TLS auth; bind to socket.", false},
	{2376, "Docker API (TLS)", false, "", "", false},
	{4444, "Metasploit", true, "Port commonly used by Metasploit payloads", "If this is open unexpectedly, investigate immediately.", false},
	{4848, "GlassFish Admin", true, "GlassFish admin console exposed", "Restrict to localhost or internal network.", false},
	{5601, "Kibana", true, "Kibana without auth exposes all Elasticsearch data", "Enable Kibana auth; restrict to internal network.", false},
	{6000, "X11", true, "X11 exposed to internet allows screen capture / input injection", "Never expose X11 externally; use X11 over SSH tunnel.", false},
	{7001, "WebLogic", true, "WebLogic often has critical RCE vulnerabilities", "Patch immediately; restrict admin access to internal network.", false},
	{8161, "ActiveMQ Admin", true, "ActiveMQ admin console with default credentials", "Change default credentials; restrict to internal network.", false},
	{8500, "Consul", true, "Consul API exposed = full cluster control", "Bind to internal network; enable ACLs.", false},
	{8834, "Nessus", false, "", "", false},
	{9042, "Cassandra", true, "Cassandra without auth should not be internet-accessible", "Enable auth; bind to internal network.", false},
	{9443, "VMware / Various", false, "", "", false},
	{10000, "Webmin", true, "Webmin has a history of critical RCE vulns", "Upgrade and patch; restrict to internal network.", false},
	{50000, "SAP", true, "SAP message server exposed", "Restrict to internal network.", false},
	{61616, "ActiveMQ Broker", true, "ActiveMQ broker exposed; susceptible to deserialization RCE", "Restrict to internal network; upgrade to patched version.", false},
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	host, err := utils.ExtractHost(cfg.Target)
	if err != nil {
		return fmt.Errorf("portscan: extract host: %w", err)
	}

	ports := eligiblePorts(cfg.Level)
	utils.LogDebug(cfg.Verbose, "portscan: scanning %d ports on %s", len(ports), host)

	type result struct {
		def    portDef
		banner string
		open   bool
	}

	resultsCh := make(chan result, len(ports))
	// Port scanning is I/O-bound and fast; allow more concurrency than the
	// global thread count so the scan doesn't bottleneck on port probes.
	sem := make(chan struct{}, cfg.Threads*4)
	var wg sync.WaitGroup

	limiter := delay.FromConfig(cfg.RateLimit/2, cfg.DelayStrategy, cfg.MaxDelayMs)
	var limMu sync.Mutex

	dialTimeout := time.Duration(cfg.Timeout) * time.Second / 4
	if dialTimeout < 2*time.Second {
		dialTimeout = 2 * time.Second
	}

	for _, pd := range ports {
		wg.Add(1)
		go func(p portDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, strconv.Itoa(p.port))
			conn, err := net.DialTimeout("tcp", addr, dialTimeout)
			if err != nil {
				return
			}

			banner := ""
			if p.grabBanner {
				banner = grabBanner(conn, dialTimeout)
			} else {
				conn.Close()
			}

			resultsCh <- result{def: p, banner: banner, open: true}

			limMu.Lock()
			if cfg.RateLimit > 0 {
				limiter.Wait()
			}
			limMu.Unlock()
		}(pd)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		if !r.open {
			continue
		}

		title := fmt.Sprintf("Open port: %d/tcp (%s)", r.def.port, r.def.service)
		desc := fmt.Sprintf("Port %d/tcp (%s) is open and accepting connections.", r.def.port, r.def.service)
		if r.banner != "" {
			desc += fmt.Sprintf(" Banner: %q", r.banner)
		}

		sev := scanner.SeverityInfo
		ftype := scanner.FindingInformational
		remediation := ""

		if r.def.risky {
			sev = scanner.SeverityHigh
			ftype = scanner.FindingWeakness
			desc += " " + r.def.riskNote
			remediation = r.def.remediation
		}

		findings <- scanner.Finding{
			ID:           fmt.Sprintf("port-%d", r.def.port),
			Module:       m.Name(),
			Type:         ftype,
			Title:        title,
			Description:  desc,
			Severity:     sev,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			Remediation:  remediation,
			Evidence:     r.banner,
			Metadata:     map[string]string{"port": strconv.Itoa(r.def.port), "service": r.def.service},
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

// grabBanner attempts to read a service banner from an already-open connection.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout / 2))

	// Some services (HTTP, FTP, SMTP, SSH) send a banner on connect.
	// Others (like MySQL) need a trigger packet — skip those here.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 200 {
			line = line[:200]
		}
		return line
	}
	return ""
}

// eligiblePorts returns the port list for the given scan level.
func eligiblePorts(level scanner.ScanLevel) []portDef {
	var ports []portDef
	for _, p := range knownPorts {
		switch level {
		case scanner.Level1:
			// Only the first 18 entries (Level 1 block)
			if p.port <= 27017 && len(ports) < 18 {
				ports = append(ports, p)
			}
		case scanner.Level2:
			if p.port != 161 && p.port != 500 && p.port < 2375 {
				ports = append(ports, p)
			}
			// include level 2 extras too
			if p.port >= 69 && p.port <= 27018 {
				ports = append(ports, p)
			}
		default: // Level 3 = all
			ports = append(ports, p)
		}
	}
	// Deduplicate
	seen := map[int]bool{}
	out := ports[:0]
	for _, p := range knownPorts {
		if seen[p.port] {
			continue
		}
		switch level {
		case scanner.Level1:
			if p.port == 21 || p.port == 22 || p.port == 23 || p.port == 25 ||
				p.port == 53 || p.port == 80 || p.port == 110 || p.port == 143 ||
				p.port == 443 || p.port == 445 || p.port == 993 || p.port == 995 ||
				p.port == 3306 || p.port == 3389 || p.port == 5432 || p.port == 6379 ||
				p.port == 8080 || p.port == 8443 || p.port == 27017 {
				out = append(out, p)
				seen[p.port] = true
			}
		case scanner.Level2:
			out = append(out, p)
			seen[p.port] = true
		default:
			out = append(out, p)
			seen[p.port] = true
		}
	}
	return out
}
