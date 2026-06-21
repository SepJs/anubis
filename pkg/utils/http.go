package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPConfig holds configuration for HTTP requests
type HTTPConfig struct {
	Timeout    time.Duration
	ProxyURL   string
	UserAgent  string
	SkipVerify bool
	Headers    map[string]string
	RateLimit  int // milliseconds between requests
}

// DefaultHTTPConfig returns sensible defaults
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:   30 * time.Second,
		UserAgent: "Mozilla/5.0 (compatible; Anubis-Scanner/1.0; Security-Testing)",
		RateLimit: 100,
	}
}

// BuildHTTPClient creates an http.Client from config
func BuildHTTPClient(cfg HTTPConfig) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec
		},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}, nil
}

// DoRequest performs an HTTP request with configured headers
func DoRequest(client *http.Client, method, targetURL string, body io.Reader, cfg HTTPConfig) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	if cfg.RateLimit > 0 {
		time.Sleep(time.Duration(cfg.RateLimit) * time.Millisecond)
	}

	return client.Do(req)
}

// NormalizeTarget ensures target has a scheme
func NormalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ExtractHost returns hostname from URL
func ExtractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsHTTPS checks if a URL uses HTTPS
func IsHTTPS(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

// SafeClose closes a body silently
func SafeClose(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}
