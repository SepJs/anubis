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

type HTTPConfig struct {
	Timeout    time.Duration
	ProxyURL   string
	UserAgent  string
	SkipVerify bool
	Headers    map[string]string
	RateLimit  int
}

type DoRequestOptions struct {
	Method   string
	URL      string
	Body     io.Reader
	Headers  map[string]string
	Timeout  time.Duration
	Cookies  []*http.Cookie
}

func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:   30 * time.Second,
		UserAgent: "Mozilla/5.0 (compatible; Anubis-Scanner/1.0; Security-Testing)",
		RateLimit: 100,
	}
}

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

func NormalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

func ExtractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func IsHTTPS(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

func SafeClose(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}
