package portscan

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/utils"
)

// Module implements scanner.Module for port scanning
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string        { return "PORT_SCAN" }
func (m *Module) Description() string { return "Open port and service detection" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

// commonPorts contains the ports scanned at each level
var level1Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017,
}

var level2ExtraPorts = []int{
	69, 161, 389, 636, 1433, 1521, 2049, 3000, 4000, 4443,
	5000, 5601, 8000, 8001, 8008, 8081, 8082, 8083, 9000, 9090,
	9200, 9300, 10000, 11211, 15672, 27018, 50000, 61616,
}

var level3ExtraPorts = []int{
	// Wider sweep for deep scans — top 1000 common ports sample
	7, 13, 17, 19, 37, 42, 43, 49, 79, 81, 82, 83, 84, 85, 88,
	111, 119, 135, 137, 139, 177, 199, 389, 427, 444, 458,
	554, 631, 666, 771, 800, 801, 808, 843, 873, 902, 990,
	1080, 1194, 1337, 1723, 1883, 2082, 2083, 2086, 2087,
	2222, 2375, 2376, 3128, 3690, 4040, 4848, 5555, 5900,
	5985, 6000, 6001, 6443, 6666, 7000, 7001, 7070, 7443,
	7777, 8161, 8443, 8500, 8834, 8880, 9001, 9042, 9200,
	9418, 9443, 9999, 10443, 27017, 28017, 49152, 49153,
}

// serviceMap maps common ports to service names
var serviceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
	1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
	6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
	9200: "Elasticsearch", 27017: "MongoDB",
}

// riskyPorts are flagged with a higher severity
var riskyPorts = map[int]string{
	23:    "Telnet is unencrypted and should be disabled",
	3389:  "RDP exposed to internet increases attack surface",
	5900:  "VNC should not be internet-accessible without VPN",
	6379:  "Redis should not be internet-accessible; no auth by default",
	9200:  "Elasticsearch exposed without auth is a critical risk",
	27017: "MongoDB exposed without auth is a critical risk",
	1433:  "MSSQL should not be internet-accessible",
	3306:  "MySQL should not be internet-accessible",
	5432:  "PostgreSQL should not be internet-accessible",
}

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	host, err := utils.ExtractHost(cfg.Target)
	if err != nil {
		return fmt.Errorf("portscan: extract host: %w", err)
	}

	ports := buildPortList(cfg.Level)
	utils.LogDebug(cfg.Verbose, "portscan: scanning %d ports on %s", len(ports), host)

	type result struct {
		port int
		open bool
	}

	resultsCh := make(chan result, len(ports))
	sem := make(chan struct{}, cfg.Threads*2) // allow more concurrency for I/O-bound port scanning
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := net.JoinHostPort(host, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, time.Duration(cfg.Timeout)*time.Second/4)
			if err == nil {
				_ = conn.Close()
				resultsCh <- result{port: p, open: true}
			}

			if cfg.RateLimit > 0 {
				time.Sleep(time.Duration(cfg.RateLimit/2) * time.Millisecond)
			}
		}(port)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		if !r.open {
			continue
		}

		svc, ok := serviceMap[r.port]
		if !ok {
			svc = "Unknown"
		}

		severity := scanner.SeverityInfo
		confidence := scanner.ConfidenceConfirmed
		description := fmt.Sprintf("Port %d/tcp is open (%s)", r.port, svc)
		remediation := ""

		if risky, found := riskyPorts[r.port]; found {
			severity = scanner.SeverityHigh
			description = fmt.Sprintf("Risky port %d/tcp (%s) is open and internet-accessible. %s", r.port, svc, risky)
			remediation = buildRemediation(r.port, svc)
		}

		findings <- scanner.Finding{
			ID:          fmt.Sprintf("port-%d", r.port),
			Module:      m.Name(),
			Type:        scanner.FindingInformational,
			Title:       fmt.Sprintf("Open port: %d/tcp (%s)", r.port, svc),
			Description: description,
			Severity:    severity,
			Confidence:  confidence,
			Endpoint:    host,
			Remediation: remediation,
			References:  []string{"https://www.iana.org/assignments/service-names-port-numbers"},
			DiscoveredAt: time.Now(),
		}
	}

	return nil
}

func buildPortList(level scanner.ScanLevel) []int {
	ports := make([]int, len(level1Ports))
	copy(ports, level1Ports)
	if level >= scanner.Level2 {
		ports = append(ports, level2ExtraPorts...)
	}
	if level >= scanner.Level3 {
		ports = append(ports, level3ExtraPorts...)
	}
	// Deduplicate
	seen := make(map[int]bool)
	unique := ports[:0]
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

func buildRemediation(port int, svc string) string {
	switch port {
	case 23:
		return "Replace Telnet with SSH. Disable the Telnet service: `systemctl disable telnet` or equivalent."
	case 3389:
		return "Place RDP behind a VPN. Restrict access via firewall rules to trusted IPs only."
	case 5900:
		return "Disable VNC or restrict to localhost. Use SSH tunneling: `ssh -L 5900:localhost:5900 user@host`."
	case 6379:
		return "Bind Redis to 127.0.0.1, enable AUTH, and use a firewall rule to block external access."
	case 9200:
		return "Enable Elasticsearch security (X-Pack), bind to localhost, and protect with firewall rules."
	case 27017:
		return "Enable MongoDB authentication, bind to localhost, and restrict access via firewall."
	default:
		return fmt.Sprintf("Restrict external access to %s (port %d) via firewall unless required for your service.", svc, port)
	}
}
