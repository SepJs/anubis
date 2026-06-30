package evasion

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

type HeaderRandomizer struct {
	rng      *rand.Rand
	mu       sync.Mutex
	templates []HeaderTemplate
}

type HeaderTemplate struct {
	Name  string
	Value string
}

type BrowserFingerprint struct {
	UserAgent     string
	Accept        string
	AcceptLang    string
	AcceptEnc     string
	SecChUA       string
	SecChUAMobile string
	SecChUAArch   string
	SecChUAPlatform string
}

var desktopFingerprints = []BrowserFingerprint{
	{
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Accept:        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLang:    "en-US,en;q=0.9",
		AcceptEnc:     "gzip, deflate, br",
	},
	{
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		Accept:        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLang:    "en-US,en;q=0.9",
		AcceptEnc:     "gzip, deflate, br",
	},
	{
		UserAgent:     "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0 Gecko/20100101 Firefox/127.0",
		Accept:        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLang:    "en-US,en;q=0.5",
		AcceptEnc:     "gzip, deflate, br",
	},
	{
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/125.0.2535.67 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
		Accept:        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLang:    "en-US,en;q=0.9",
		AcceptEnc:     "gzip, deflate, br",
	},
}

var toolFingerprints = map[string][]HeaderTemplate{
	"curl": {
		{Name: "User-Agent", Value: "curl/8.7.1"},
		{Name: "Accept", Value: "*/*"},
	},
	"wget": {
		{Name: "User-Agent", Value: "Wget/1.24.5"},
		{Name: "Accept", Value: "*/*"},
		{Name: "Connection", Value: "Keep-Alive"},
	},
	"chrome": {
		{Name: "User-Agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
		{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		{Name: "Accept-Language", Value: "en-US,en;q=0.9"},
		{Name: "Sec-Ch-Ua", Value: `"Chromium";v="125", "Not.A/Brand";v="24"`},
		{Name: "Sec-Ch-Ua-Mobile", Value: "?0"},
		{Name: "Sec-Ch-Ua-Platform", Value: `"Windows"`},
	},
}

func NewHeaderRandomizer() *HeaderRandomizer {
	return &HeaderRandomizer{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (hr *HeaderRandomizer) RandomizeHeaders(req *http.Request, fingerprint string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	if fp, ok := toolFingerprints[fingerprint]; ok {
		for _, h := range fp {
			req.Header.Set(h.Name, h.Value)
		}
		return
	}

	fp := desktopFingerprints[hr.rng.Intn(len(desktopFingerprints))]
	req.Header.Set("User-Agent", fp.UserAgent)
	req.Header.Set("Accept", fp.Accept)
	req.Header.Set("Accept-Language", fp.AcceptLang)
	req.Header.Set("Accept-Encoding", fp.AcceptEnc)

	if hr.rng.Float64() > 0.5 {
		req.Header.Set("Cache-Control", "no-cache")
	}
	if hr.rng.Float64() > 0.7 {
		req.Header.Set("DNT", "1")
	}
	if hr.rng.Float64() > 0.8 {
		req.Header.Set("Sec-GPC", "1")
	}

	extraHeaders := []string{
		"Upgrade-Insecure-Requests: 1",
		fmt.Sprintf("Sec-Fetch-Dest: %s", hr.randomSecFetch()),
		fmt.Sprintf("Sec-Fetch-Mode: %s", hr.randomSecFetchMode()),
		"Sec-Fetch-Site: none",
		"Sec-Fetch-User: ?1",
	}
	for _, h := range extraHeaders {
		parts := splitHeader(h)
		if len(parts) == 2 {
			if hr.rng.Float64() > 0.3 {
				req.Header.Set(parts[0], parts[1])
			}
		}
	}
}

func (hr *HeaderRandomizer) randomSecFetch() string {
	choices := []string{"document", "image", "frame", "empty"}
	return choices[hr.rng.Intn(len(choices))]
}

func (hr *HeaderRandomizer) randomSecFetchMode() string {
	choices := []string{"navigate", "no-cors", "cors", "same-origin"}
	return choices[hr.rng.Intn(len(choices))]
}

func splitHeader(h string) []string {
	for i := 0; i < len(h); i++ {
		if h[i] == ':' {
			return []string{h[:i], h[i+2:]}
		}
	}
	return nil
}
