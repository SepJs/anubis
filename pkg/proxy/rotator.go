// Package proxy implements a SOCKS5/HTTP/HTTPS proxy rotator with health
// checking, automatic failover, and round-robin distribution.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyType int

const (
	ProxyHTTP ProxyType = iota
	ProxyHTTPS
	ProxySOCKS5
	ProxySOCKS4
)

type Proxy struct {
	URL       *url.URL
	Type      ProxyType
	Latency   time.Duration
	LastUsed  time.Time
	FailCount atomic.Int32
	Country   string
}

type Rotator struct {
	proxies    []*Proxy
	current    atomic.Int64
	mu         sync.RWMutex
	client     *http.Client
	healthURL  string
	healthInterval time.Duration
	maxFails   int32
}

func NewRotator() *Rotator {
	r := &Rotator{
		healthURL:      "http://httpbin.org/ip",
		healthInterval: 30 * time.Second,
		maxFails:       3,
	}
	r.client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    20,
		},
	}
	go r.healthCheckLoop()
	return r
}

func (rot *Rotator) AddProxy(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	p := &Proxy{
		URL:  u,
		Type: classifyProxy(u),
		LastUsed: time.Now(),
	}

	rot.mu.Lock()
	rot.proxies = append(rot.proxies, p)
	rot.mu.Unlock()
	return nil
}

func (rot *Rotator) AddProxies(urls []string) error {
	for _, u := range urls {
		if err := rot.AddProxy(u); err != nil {
			return err
		}
	}
	return nil
}

func (rot *Rotator) Next() *Proxy {
	rot.mu.RLock()
	defer rot.mu.RUnlock()

	if len(rot.proxies) == 0 {
		return nil
	}

	for i := 0; i < len(rot.proxies); i++ {
		idx := int(rot.current.Add(1)) % len(rot.proxies)
		p := rot.proxies[idx]
		if p.FailCount.Load() < rot.maxFails {
			p.LastUsed = time.Now()
			return p
		}
	}
	return rot.proxies[int(rot.current.Load())%len(rot.proxies)]
}

func (rot *Rotator) TransportForProxy(p *Proxy) (*http.Transport, error) {
	if p == nil {
		return &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
		}, nil
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
	}

	switch p.Type {
	case ProxyHTTP, ProxyHTTPS:
		transport.Proxy = http.ProxyURL(p.URL)
	case ProxySOCKS5:
		dialer, err := proxySOCKS5Dialer(p.URL)
		if err != nil {
			return nil, err
		}
		transport.DialContext = dialer
	default:
		return nil, fmt.Errorf("unsupported proxy type: %v", p.Type)
	}

	return transport, nil
}

func (rot *Rotator) MarkFailed(p *Proxy) {
	if p == nil {
		return
	}
	p.FailCount.Add(1)
}

func (rot *Rotator) MarkSuccess(p *Proxy) {
	if p == nil {
		return
	}
	p.FailCount.Store(0)
}

func (rot *Rotator) Count() int {
	rot.mu.RLock()
	defer rot.mu.RUnlock()
	return len(rot.proxies)
}

func (rot *Rotator) HealthyCount() int {
	rot.mu.RLock()
	defer rot.mu.RUnlock()
	count := 0
	for _, p := range rot.proxies {
		if p.FailCount.Load() < rot.maxFails {
			count++
		}
	}
	return count
}

func (rot *Rotator) healthCheckLoop() {
	ticker := time.NewTicker(rot.healthInterval)
	defer ticker.Stop()

	for range ticker.C {
		rot.checkAll()
	}
}

func (rot *Rotator) checkAll() {
	rot.mu.RLock()
	proxies := make([]*Proxy, len(rot.proxies))
	copy(proxies, rot.proxies)
	rot.mu.RUnlock()

	for _, p := range proxies {
		start := time.Now()
		transport, err := rot.TransportForProxy(p)
		if err != nil {
			p.FailCount.Add(1)
			continue
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		}
		resp, err := client.Get(rot.healthURL)
		if err != nil {
			p.FailCount.Add(1)
			continue
		}
		resp.Body.Close()
		p.Latency = time.Since(start)
		p.FailCount.Store(0)
	}
}

func (rot *Rotator) Close() error {
	return nil
}

func classifyProxy(u *url.URL) ProxyType {
	switch u.Scheme {
	case "http":
		return ProxyHTTP
	case "https":
		return ProxyHTTPS
	case "socks5", "socks5h":
		return ProxySOCKS5
	case "socks4", "socks4a":
		return ProxySOCKS4
	default:
		return ProxyHTTP
	}
}

func proxySOCKS5Dialer(u *url.URL) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}

		port := 80
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}

		ip := net.ParseIP(host)
		var atyp byte = 3
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				atyp = 1
			} else {
				atyp = 4
			}
		}

		msg := []byte{5, 1, 0}
		if _, err := conn.Write(msg); err != nil {
			conn.Close()
			return nil, err
		}

		buf := make([]byte, 2)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, err
		}

		var addrBytes []byte
		if atyp == 1 {
			addrBytes = ip.To4()
		} else if atyp == 4 {
			addrBytes = ip.To16()
		} else {
			addrBytes = []byte(host)
		}

		req := []byte{5, 1, 0, atyp}
		if atyp == 3 {
			req = append(req, byte(len(addrBytes)))
		}
		req = append(req, addrBytes...)
		req = append(req, byte(port>>8), byte(port))

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, err
		}

		resp := make([]byte, 4)
		if _, err := conn.Read(resp); err != nil {
			conn.Close()
			return nil, err
		}

		if resp[1] != 0 {
			conn.Close()
			return nil, errors.New("SOCKS5 connection rejected")
		}

		return conn, nil
	}, nil
}
