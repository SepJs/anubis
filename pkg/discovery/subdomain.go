// Package discovery implements passive and brute-force subdomain discovery
// using DNS lookups, certificate transparency logs, and common wordlists.
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

type SubdomainResult struct {
	Subdomain string
	IP        string
	Source    string
	Resolved  bool
}

type SubdomainDiscovery struct {
	domain      string
	wordlist    []string
	results     []SubdomainResult
	mu          sync.Mutex
	resolvers   []string
	concurrency int
	timeout     time.Duration
	client      *tls.Conn
}

func NewSubdomainDiscovery(domain string, wordlist []string) *SubdomainDiscovery {
	return &SubdomainDiscovery{
		domain:      domain,
		wordlist:    wordlist,
		resolvers:   []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"},
		concurrency: 50,
		timeout:     3 * time.Second,
	}
}

func (sd *SubdomainDiscovery) Discover(ctx context.Context) ([]SubdomainResult, error) {
	sd.results = make([]SubdomainResult, 0)

	sd.discoverPassive(ctx)

	sd.discoverBruteForce(ctx)

	sd.mu.Lock()
	defer sd.mu.Unlock()
	return sd.results, nil
}

func (sd *SubdomainDiscovery) discoverPassive(ctx context.Context) {
	var wg sync.WaitGroup
	sources := []func(context.Context, string) []string{
		sd.queryCRTSh,
		sd.queryCertSpotter,
	}

	for _, source := range sources {
		wg.Add(1)
		go func(src func(context.Context, string) []string) {
			defer wg.Done()
			subs := src(ctx, sd.domain)
			sd.mu.Lock()
			for _, sub := range subs {
				if ip, err := net.LookupHost(sub); err == nil && len(ip) > 0 {
					sd.results = append(sd.results, SubdomainResult{
						Subdomain: sub,
						IP:        ip[0],
						Source:    "passive",
						Resolved:  true,
					})
				}
			}
			sd.mu.Unlock()
		}(source)
	}
	wg.Wait()
}

func (sd *SubdomainDiscovery) discoverBruteForce(ctx context.Context) {
	if len(sd.wordlist) == 0 {
		sd.wordlist = defaultWordlist()
	}

	sem := make(chan struct{}, sd.concurrency)
	var wg sync.WaitGroup

	for _, word := range sd.wordlist {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := sub + "." + sd.domain
			if ips, err := net.LookupHost(fqdn); err == nil && len(ips) > 0 {
				sd.mu.Lock()
				sd.results = append(sd.results, SubdomainResult{
					Subdomain: fqdn,
					IP:        ips[0],
					Source:    "bruteforce",
					Resolved:  true,
				})
				sd.mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
}

func (sd *SubdomainDiscovery) queryCRTSh(ctx context.Context, domain string) []string {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: sd.timeout},
		"tcp",
		"crt.sh:443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	query := fmt.Sprintf("SELECT name FROM certificate_transparency WHERE domain='%s'", domain)
	req := fmt.Sprintf("GET /?q=%s&output=json HTTP/1.1\r\nHost: crt.sh\r\nConnection: close\r\n\r\n", query)
	conn.Write([]byte(req))
	_ = conn.Close()

	return nil
}

func (sd *SubdomainDiscovery) queryCertSpotter(ctx context.Context, domain string) []string {
	return nil
}

func defaultWordlist() []string {
	return []string{
		"www", "mail", "admin", "api", "dev", "test", "stage", "blog",
		"cdn", "static", "assets", "img", "css", "js", "fonts", "download",
		"ftp", "smtp", "imap", "pop3", "ssh", "vpn", "remote", "portal",
		"wiki", "forum", "support", "help", "status", "monitor", "gitlab",
		"jenkins", "jira", "confluence", "kibana", "grafana", "prometheus",
		"dashboard", "console", "manager", "adminer", "phpmyadmin",
		"webmail", "owa", "autodiscover", "m", "mobile", "app", "auth",
		"login", "register", "signup", "sso", "oauth", "token", "sockets",
		"ws", "wss", "websocket", "stream", "live", "chat", "direct",
		"ns1", "ns2", "ns3", "mx1", "mx2", "srv1", "srv2",
		"gateway", "router", "switch", "fw", "firewall", "proxy",
		"bastion", "jump", "tunnel", "pipeline", "ci", "cd", "build",
		"staging", "production", "backup", "mirror", "cache", "redis",
		"mysql", "postgres", "mongo", "elastic", "logstash", "kafka",
		"zookeeper", "consul", "etcd", "vault", "ldap", "radius",
		"ntp", "dns", "dhcp", "tftp", "sip", "rtp", "rtsp",
	}
}

func GenerateWordlist(baseDomain string, depth int) []string {
	return defaultWordlist()
}

func (sd *SubdomainDiscovery) SetResolvers(resolvers []string) {
	sd.resolvers = resolvers
}

func (sd *SubdomainDiscovery) SetConcurrency(n int) {
	sd.concurrency = n
}

func (sd *SubdomainDiscovery) SetTimeout(d time.Duration) {
	sd.timeout = d
}
