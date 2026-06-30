package evasion

import (
	"math/rand"
	"net/http"
	"strings"
)

type FingerprintMimic struct {
	profiles map[string]FingerprintProfile
}

type FingerprintProfile struct {
	Name    string
	Headers map[string]string
	Order   []string
}

func NewFingerprintMimic() *FingerprintMimic {
	return &FingerprintMimic{
		profiles: map[string]FingerprintProfile{
			"curl": {
				Name: "curl",
				Headers: map[string]string{
					"User-Agent":      "curl/8.7.1",
					"Accept":          "*/*",
					"Content-Type":    "application/x-www-form-urlencoded",
				},
				Order: []string{"User-Agent", "Accept", "Content-Type"},
			},
			"wget": {
				Name: "wget",
				Headers: map[string]string{
					"User-Agent": "Wget/1.24.5",
					"Accept":     "*/*",
					"Connection": "Keep-Alive",
				},
				Order: []string{"User-Agent", "Accept", "Connection"},
			},
			"chrome": {
				Name: "chrome",
				Headers: map[string]string{
					"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
					"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
					"Accept-Language": "en-US,en;q=0.9",
					"Accept-Encoding": "gzip, deflate, br",
					"Sec-Ch-Ua":       `"Chromium";v="125", "Not.A/Brand";v="24"`,
					"Sec-Ch-Ua-Mobile": "?0",
					"Sec-Ch-Ua-Platform": `"Windows"`,
				},
				Order: []string{
					"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
					"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
				},
			},
			"safari": {
				Name: "safari",
				Headers: map[string]string{
					"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
					"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
					"Accept-Language": "en-US,en;q=0.9",
					"Accept-Encoding": "gzip, deflate, br",
				},
				Order: []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"},
			},
			"firefox": {
				Name: "firefox",
				Headers: map[string]string{
					"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
					"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
					"Accept-Language": "en-US,en;q=0.5",
					"Accept-Encoding": "gzip, deflate, br",
				},
				Order: []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"},
			},
		},
	}
}

func (fm *FingerprintMimic) ApplyProfile(req *http.Request, profileName string) {
	profileName = strings.ToLower(profileName)
	profile, ok := fm.profiles[profileName]
	if !ok {
		return
	}

	for k, v := range profile.Headers {
		req.Header.Set(k, v)
	}
}

func (fm *FingerprintMimic) ApplyRandomBrowserProfile(req *http.Request) {
	browsers := []string{"chrome", "firefox", "safari"}
	idx := rand.Intn(len(browsers))
	fm.ApplyProfile(req, browsers[idx])
}

func (fm *FingerprintMimic) ProfileNames() []string {
	names := make([]string, 0, len(fm.profiles))
	for n := range fm.profiles {
		names = append(names, n)
	}
	return names
}

func (fm *FingerprintMimic) ValidateFingerprint(req *http.Request, profileName string) bool {
	profile, ok := fm.profiles[profileName]
	if !ok {
		return false
	}
	for k, v := range profile.Headers {
		if req.Header.Get(k) != v {
			return false
		}
	}
	return true
}

func (fm *FingerprintMimic) FingerprintIntegrityCheck(req *http.Request) map[string]bool {
	results := make(map[string]bool)
	for name, profile := range fm.profiles {
		match := true
		for k, v := range profile.Headers {
			if !strings.EqualFold(req.Header.Get(k), v) {
				match = false
				break
			}
		}
		results[name] = match
	}
	return results
}
