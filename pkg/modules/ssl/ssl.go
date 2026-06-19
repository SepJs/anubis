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
	"github.com/innervoid/anubis/pkg/utils"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string             { return "SSL_CHECK" }
func (m *Module) Description() string      { return "SSL/TLS certificate and configuration analysis" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }

func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	host, err := utils.ExtractHost(cfg.Target)
	if err != nil {
		return fmt.Errorf("ssl: extract host: %w", err)
	}

	if cfg.RateLimit > 0 {
		time.Sleep(time.Duration(cfg.RateLimit) * time.Millisecond)
	}

	addr := net.JoinHostPort(host, "443")
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Duration(cfg.Timeout) * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — we check manually
			ServerName:         host,
		},
	)
	if err != nil {
		findings <- scanner.Finding{
			ID:           "ssl-no-tls",
			Module:       m.Name(),
			Type:         scanner.FindingInformational,
			Title:        "HTTPS not available on port 443",
			Description:  fmt.Sprintf("Could not establish TLS connection to %s:443 — %v", host, err),
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			Remediation:  "Enable HTTPS with a valid TLS certificate. Use Let's Encrypt for free certificates.",
			DiscoveredAt: time.Now(),
		}
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// --- Certificate checks ---
	for _, cert := range state.PeerCertificates {
		checkCert(cert, host, findings, m.Name())
	}

	// --- Protocol version checks ---
	checkProtocol(state, host, findings, m.Name())

	// --- Cipher suite checks ---
	checkCipher(state, host, findings, m.Name())

	return nil
}

func checkCert(cert *x509.Certificate, host string, findings chan<- scanner.Finding, module string) {
	now := time.Now()

	// Expired?
	if now.After(cert.NotAfter) {
		findings <- scanner.Finding{
			ID:           "ssl-cert-expired",
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        "SSL/TLS Certificate Expired",
			Description:  fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
			Severity:     scanner.SeverityCritical,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			Remediation:  "Renew the TLS certificate immediately. Use automated renewal (Let's Encrypt + Certbot) to prevent recurrence.",
			CVSSScore:    7.5,
			References:   []string{"https://www.rfc-editor.org/rfc/rfc5280"},
			DiscoveredAt: time.Now(),
		}
	}

	// Expiring soon (within 30 days)?
	if now.Before(cert.NotAfter) && cert.NotAfter.Sub(now) < 30*24*time.Hour {
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		findings <- scanner.Finding{
			ID:           "ssl-cert-expiring",
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        fmt.Sprintf("SSL/TLS Certificate Expiring Soon (%d days)", days),
			Description:  fmt.Sprintf("Certificate expires on %s — %d days remaining", cert.NotAfter.Format("2006-01-02"), days),
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			Remediation:  "Renew the certificate before it expires. Configure auto-renewal to prevent outages.",
			DiscoveredAt: time.Now(),
		}
	}

	// Self-signed?
	if cert.Issuer.CommonName == cert.Subject.CommonName {
		findings <- scanner.Finding{
			ID:           "ssl-self-signed",
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        "Self-Signed SSL Certificate",
			Description:  "The server presents a self-signed certificate. Browsers will warn users and trust cannot be established.",
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceSuspected,
			Endpoint:     host,
			Remediation:  "Replace with a certificate from a trusted CA. Let's Encrypt provides free certificates.",
			DiscoveredAt: time.Now(),
		}
	}

	// Weak key?
	keySize := certKeySize(cert)
	if keySize > 0 && keySize < 2048 {
		findings <- scanner.Finding{
			ID:           "ssl-weak-key",
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Weak TLS Key Size: %d bits", keySize),
			Description:  fmt.Sprintf("Certificate uses a %d-bit key, which is below the recommended 2048 bits minimum.", keySize),
			Severity:     scanner.SeverityHigh,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			CVSSScore:    6.0,
			Remediation:  "Reissue the certificate with at least 2048-bit RSA or a 256-bit ECDSA key.",
			DiscoveredAt: time.Now(),
		}
	}

	// Hostname mismatch?
	if err := cert.VerifyHostname(host); err != nil {
		findings <- scanner.Finding{
			ID:           "ssl-hostname-mismatch",
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        "SSL Certificate Hostname Mismatch",
			Description:  fmt.Sprintf("Certificate does not match hostname %q: %v", host, err),
			Severity:     scanner.SeverityHigh,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			CVSSScore:    6.8,
			Remediation:  "Issue a certificate that covers the correct hostname or add a Subject Alternative Name (SAN) entry.",
			DiscoveredAt: time.Now(),
		}
	}
}

func checkProtocol(state tls.ConnectionState, host string, findings chan<- scanner.Finding, module string) {
	deprecatedVersions := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
	}
	if name, deprecated := deprecatedVersions[state.Version]; deprecated {
		findings <- scanner.Finding{
			ID:           "ssl-deprecated-protocol",
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Deprecated TLS Protocol: %s", name),
			Description:  fmt.Sprintf("Server negotiated %s which is deprecated and vulnerable to downgrade attacks (POODLE, BEAST).", name),
			Severity:     scanner.SeverityHigh,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			CVSSScore:    6.5,
			OWASPMapping: "A02:2021 – Cryptographic Failures",
			Remediation:  "Disable TLS 1.0 and 1.1. Configure server to accept only TLS 1.2 and TLS 1.3.",
			VulnCode:     "# nginx\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n",
			SecureCode:   "# nginx\nssl_protocols TLSv1.2 TLSv1.3;\n",
			DiscoveredAt: time.Now(),
		}
	}
}

func checkCipher(state tls.ConnectionState, host string, findings chan<- scanner.Finding, module string) {
	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:         "RC4",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "3DES",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "RC4",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "RC4",
	}

	suiteName := tls.CipherSuiteName(state.CipherSuite)
	if weakName, weak := weakCiphers[state.CipherSuite]; weak {
		findings <- scanner.Finding{
			ID:           "ssl-weak-cipher",
			Module:       module,
			Type:         scanner.FindingVulnerability,
			Title:        fmt.Sprintf("Weak TLS Cipher Suite: %s (%s)", suiteName, weakName),
			Description:  fmt.Sprintf("Server negotiated cipher suite %s which uses the broken %s algorithm.", suiteName, weakName),
			Severity:     scanner.SeverityHigh,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			CVSSScore:    6.0,
			OWASPMapping: "A02:2021 – Cryptographic Failures",
			Remediation:  "Disable weak cipher suites. Configure only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
			DiscoveredAt: time.Now(),
		}
	}

	// Check for forward secrecy
	if !strings.Contains(suiteName, "ECDHE") && !strings.Contains(suiteName, "DHE") {
		findings <- scanner.Finding{
			ID:           "ssl-no-pfs",
			Module:       module,
			Type:         scanner.FindingWeakness,
			Title:        "No Perfect Forward Secrecy",
			Description:  fmt.Sprintf("Cipher suite %s does not provide Perfect Forward Secrecy (PFS). Past sessions can be decrypted if the private key is compromised.", suiteName),
			Severity:     scanner.SeverityMedium,
			Confidence:   scanner.ConfidenceConfirmed,
			Endpoint:     host,
			Remediation:  "Prefer ECDHE cipher suites to enable Perfect Forward Secrecy.",
			DiscoveredAt: time.Now(),
		}
	}
}

// certKeySize returns the bit length of the certificate's public key.
// Supports RSA and ECDSA keys — the two types used in the vast majority of
// web certificates. Returns 0 for unsupported key types (e.g. Ed25519).
func certKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}
