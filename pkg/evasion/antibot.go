package evasion

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type HoneypotDetector struct {
	honeypotSignatures []string
	knownHoneypotIPs   []string
	client             *http.Client
}

func NewHoneypotDetector() *HoneypotDetector {
	return &HoneypotDetector{
		honeypotSignatures: []string{
			"honeypot",
			"honeyport",
			"cowrie",
			"dionaea",
			"glastopf",
			"conpot",
			"snare",
			"tanner",
			"wordpot",
			"phpmyadmin_honeypot",
			"server: apache/2.2.22 (ubuntu)",
			"server: microsoft-iis/6.0",
		},
		knownHoneypotIPs: []string{},
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (hd *HoneypotDetector) IsHoneypot(host string) (bool, float64, error) {
	confidence := 0.0
	checks := 0

	if resp, err := hd.client.Get(fmt.Sprintf("https://%s/", host)); err == nil {
		defer resp.Body.Close()
		checks++

		server := resp.Header.Get("Server")
		for _, sig := range hd.honeypotSignatures {
			if strings.Contains(strings.ToLower(server), sig) {
				confidence += 0.3
				break
			}
		}

		if resp.Header.Get("X-Honeypot") != "" {
			confidence += 0.5
		}

		if resp.Header.Get("X-Forwarded-For") != "" {
			headerVal := resp.Header.Get("X-Forwarded-For")
			if strings.Contains(headerVal, "127.0.0.1") {
				confidence += 0.2
			}
		}

		headers := []string{"X-Honeyport", "X-Pot", "X-Honeypot-Id"}
		for _, h := range headers {
			if resp.Header.Get(h) != "" {
				confidence += 0.4
			}
		}
	}

	if ips, err := net.LookupHost(host); err == nil {
		for _, ip := range ips {
			for _, known := range hd.knownHoneypotIPs {
				if ip == known {
					confidence += 0.8
				}
			}
		}
		checks++
	}

	if checks == 0 {
		return false, 0, fmt.Errorf("unable to check host: %s", host)
	}

	result := confidence / float64(checks)
	return result > 0.4, result, nil
}

func (hd *HoneypotDetector) DetectSandboxEnvironment() bool {
	indicators := []string{
		"docker",
		"k8s",
		"kubernetes",
		"vmware",
		"virtualbox",
		"qemu",
		"xen",
	}

	hostname := getHostname()
	for _, ind := range indicators {
		if strings.Contains(strings.ToLower(hostname), ind) {
			return true
		}
	}

	return false
}

func (hd *HoneypotDetector) AddHoneypotSignature(sig string) {
	hd.honeypotSignatures = append(hd.honeypotSignatures, strings.ToLower(sig))
}

func getHostname() string {
	hostname, err := net.LookupAddr("127.0.0.1")
	if err != nil || len(hostname) == 0 {
		return ""
	}
	return hostname[0]
}
