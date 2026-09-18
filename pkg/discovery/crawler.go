package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/SepJs/anubis/pkg/utils"
)

var (
	hrefRegex  = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"'>\s#]+)["']`)
	inputRegex = regexp.MustCompile(`(?i)<(?:input|textarea|select)[^>]*name=["']([^"'>\s]+)["'][^>]*>`)
	formRegex  = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	actionAttr = regexp.MustCompile(`(?i)action=["']([^"'>\s]+)["']`)
)

// CrawlerConfig holds options for the web crawler.
type CrawlerConfig struct {
	Target        string
	MaxDepth      int
	MaxPages      int
	Timeout       time.Duration
	UserAgent     string
	SSLBypass     bool
	ProxyURL      string
	RespectLimits bool
	Verbose       bool
}

// Crawler traverses the target website collecting in-scope endpoints, links, and forms.
type Crawler struct {
	cfg       CrawlerConfig
	base      *url.URL
	client    *http.Client
	httpCfg   utils.HTTPConfig
	visited   map[string]bool
	endpoints map[string]bool
	mu        sync.Mutex
}

// NewCrawler initializes a web crawler.
func NewCrawler(cfg CrawlerConfig) (*Crawler, error) {
	parsed, err := url.Parse(utils.NormalizeTarget(cfg.Target))
	if err != nil {
		return nil, fmt.Errorf("crawler: invalid target: %w", err)
	}

	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 2
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 30
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	httpCfg := utils.HTTPConfig{
		Timeout:    cfg.Timeout,
		SkipVerify: cfg.SSLBypass,
		ProxyURL:   cfg.ProxyURL,
		UserAgent:  cfg.UserAgent,
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return nil, err
	}

	return &Crawler{
		cfg:       cfg,
		base:      parsed,
		client:    client,
		httpCfg:   httpCfg,
		visited:   make(map[string]bool),
		endpoints: make(map[string]bool),
	}, nil
}

// Crawl recursively traverses pages up to MaxDepth and MaxPages.
func (c *Crawler) Crawl(ctx context.Context) []string {
	startURL := c.base.String()
	utils.LogInfo("Crawler: Initiating target exploration on %s (depth: %d, max: %d)",
		startURL, c.cfg.MaxDepth, c.cfg.MaxPages)

	c.mu.Lock()
	c.endpoints[startURL] = true
	c.mu.Unlock()

	c.crawlURL(ctx, startURL, 1)

	c.mu.Lock()
	defer c.mu.Unlock()

	var result []string
	for ep := range c.endpoints {
		result = append(result, ep)
	}

	utils.LogSuccess("Crawler: Exploration complete — %d unique endpoint(s) mapped", len(result))
	return result
}

func (c *Crawler) crawlURL(ctx context.Context, currentURL string, depth int) {
	if depth > c.cfg.MaxDepth {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	c.mu.Lock()
	if c.visited[currentURL] || len(c.visited) >= c.cfg.MaxPages {
		c.mu.Unlock()
		return
	}
	c.visited[currentURL] = true
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
	if err != nil {
		return
	}

	if c.httpCfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.httpCfg.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer utils.SafeClose(resp.Body)

	// Only parse text/html
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "text/plain") {
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return
	}
	body := string(bodyBytes)

	// Extract standard links and assets
	links := hrefRegex.FindAllStringSubmatch(body, -1)
	var nextURLs []string

	for _, m := range links {
		if len(m) < 2 {
			continue
		}
		resolved := c.resolveLink(currentURL, m[1])
		if resolved == "" {
			continue
		}

		c.mu.Lock()
		c.endpoints[resolved] = true
		c.mu.Unlock()

		if c.isInScope(resolved) {
			nextURLs = append(nextURLs, resolved)
		}
	}

	// Extract HTML forms and create parameterized endpoints
	forms := formRegex.FindAllStringSubmatch(body, -1)
	for _, f := range forms {
		if len(f) < 3 {
			continue
		}
		formHeader := f[1]
		formBody := f[2]

		action := ""
		if act := actionAttr.FindStringSubmatch(formHeader); len(act) >= 2 {
			action = act[1]
		}
		resolvedAction := c.resolveLink(currentURL, action)
		if resolvedAction == "" {
			resolvedAction = currentURL
		}

		inputs := inputRegex.FindAllStringSubmatch(formBody, -1)
		if len(inputs) > 0 {
			u, err := url.Parse(resolvedAction)
			if err == nil {
				q := u.Query()
				for _, inp := range inputs {
					if len(inp) >= 2 && inp[1] != "" {
						q.Set(inp[1], "test")
					}
				}
				u.RawQuery = q.Encode()
				formParamURL := u.String()

				c.mu.Lock()
				c.endpoints[formParamURL] = true
				c.mu.Unlock()
			}
		}
	}

	// Recurse on discovered in-scope URLs
	for _, next := range nextURLs {
		c.mu.Lock()
		alreadyVisited := c.visited[next]
		pageLimitReached := len(c.visited) >= c.cfg.MaxPages
		c.mu.Unlock()

		if !alreadyVisited && !pageLimitReached {
			c.crawlURL(ctx, next, depth+1)
		}
	}
}

func (c *Crawler) resolveLink(baseURL, link string) string {
	link = strings.TrimSpace(link)
	if link == "" || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "tel:") {
		return ""
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)
	// Strip fragments
	resolved.Fragment = ""

	// Ensure HTTP/HTTPS
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

func (c *Crawler) isInScope(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, c.base.Host)
}
