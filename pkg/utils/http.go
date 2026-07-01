// Package utils provides shared HTTP client configuration, request helpers,
// ANSI-coloured logging, input sanitisation, and interactive prompts used
// throughout the Anubis scanner.
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

// HTTPConfig holds optional parameters for building an HTTP client.
type HTTPConfig struct {
	Timeout    time.Duration
	ProxyURL   string
	UserAgent  string
	SkipVerify bool
	Headers    map[string]string
	RateLimit  int
}

// DoRequestOptions groups optional parameters for the NewRequest helper.
type DoRequestOptions struct {
	Method   string
	URL      string
	Body     io.Reader
	Headers  map[string]string
	Timeout  time.Duration
	Cookies  []*http.Cookie
}

// DefaultHTTPConfig returns a sensible default HTTP configuration with a
// 30-second timeout and a descriptive User-Agent.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:   30 * time.Second,
		UserAgent: "Mozilla/5.0 (compatible; Anubis-Scanner/1.0; Security-Testing)",
		RateLimit: 100,
	}
}

// BuildHTTPClient constructs an http.Client from the given config, wiring
// in proxy support, TLS settings, and redirect handling.
func BuildHTTPClient(cfg HTTPConfig) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  false,
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

// DoRequest creates and sends an HTTP request with the provided config,
// applying an optional rate-limit sleep beforehand.
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

// NewRequest is a convenience wrapper that creates an HTTP request from
// structured options without modifying a shared client.
func NewRequest(opts DoRequestOptions) (*http.Response, error) {
	req, err := http.NewRequest(opts.Method, opts.URL, opts.Body)
	if err != nil {
		return nil, err
	}

	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range opts.Cookies {
		req.AddCookie(c)
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return client.Do(req)
}

// NormalizeTarget prepends http:// to a target string if no scheme is present.
func NormalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ExtractHost returns the hostname portion of a raw URL string.
func ExtractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsHTTPS returns true if the URL uses the https scheme.
func IsHTTPS(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

// SafeClose closes an io.ReadCloser, swallowing any error.
func SafeClose(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}
