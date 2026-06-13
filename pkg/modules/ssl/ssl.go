package ssl

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/innervoid/anubis/pkg/scanner"
)

// SSLModule implements the scanner.Module interface
type SSLModule struct{}

// New creates a new instance of SSLModule
func New() *SSLModule {
	return &SSLModule{}
}

// Name returns the identifier of the module
func (m *SSLModule) Name() string {
	return "SSL_CHECK"
}

// Description returns a brief explanation of the module
func (m *SSLModule) Description() string {
	return "Performs SSL/TLS certificate analysis and configuration validation"
}

// Level indicates this module runs starting from Level 1
func (m *SSLModule) Level() scanner.ScanLevel {
	return scanner.Level1
}

// Run executes the SSL scanning logic and streams findings into the channel
func (m *SSLModule) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	// Setup timeout properly by converting int to time.Duration
	timeoutDuration := time.Duration(cfg.Timeout) * time.Second
	if cfg.Timeout <= 0 {
		timeoutDuration = 10 * time.Second // Fallback default
	}

	// Clean host for TCP connection (remove protocol if present from Target)
	host := cfg.Target
	if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	} else if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	}
	
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	dialer := &net.Dialer{
		Timeout: timeoutDuration,
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return fmt.Errorf("failed to establish TLS connection: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	mainCert := state.PeerCertificates[0]
	var report strings.Builder

	report.WriteString(fmt.Sprintf("[+] Subject: %s\n", mainCert.Subject.CommonName))
	report.WriteString(fmt.Sprintf("[+] Issuer: %s\n", mainCert.Issuer.CommonName))
	report.WriteString(fmt.Sprintf("[+] Algorithm: %s\n", mainCert.SignatureAlgorithm.String()))
	
	keySize := certKeySize(mainCert)
	if keySize > 0 {
		report.WriteString(fmt.Sprintf("[+] Key Length: %d bits\n", keySize))
	}

	now := time.Now()
	if now.After(mainCert.NotAfter) {
		report.WriteString("[-] WARNING: Certificate has EXPIRED!\n")
	} else {
		report.WriteString(fmt.Sprintf("[+] Expires: %s (Valid for %.0f days)\n", mainCert.NotAfter.Format("2006-01-02"), mainCert.NotAfter.Sub(now).Hours()/24))
	}

	// Send the finalized finding strictly mapped to scanner.Finding fields
	findings <- scanner.Finding{
		ID:           fmt.Sprintf("SSL-%d", time.Now().UnixNano()),
		Module:       m.Name(),
		Type:         scanner.FindingInformational,
		Title:        "SSL/TLS Certificate Information",
		Description:  "Extracted public certificate details from target SSL/TLS configuration.",
		Evidence:     report.String(),
		Severity:     scanner.SeverityInfo,
		Confidence:   scanner.ConfidenceConfirmed,
		DiscoveredAt: time.Now(),
	}

	return nil
}

func certKeySize(cert *x509.Certificate) int {
	if cert == nil || cert.PublicKey == nil {
		return 0
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}
