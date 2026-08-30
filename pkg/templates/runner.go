package template

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/delay"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

// Engine executes loaded templates against a scan target.
type Engine struct {
	templates []*Template
	client    *http.Client
	httpCfg   utils.HTTPConfig
}

// NewEngine validates and loads all templates; errors are non-fatal and
// returned together with whatever loaded successfully.
func NewEngine(cfg scanner.ScanConfig, tplDir string) (*Engine, error) {
	if tplDir == "" {
		return &Engine{}, nil
	}
	tpls, errs := LoadDir(tplDir)
	for _, err := range errs {
		utils.LogWarn("template: %v", err)
	}
	for _, t := range tpls {
		// resolve payload files
		if t.Payloads.File != "" && len(t.Payloads.List) == 0 {
			data, err := os.ReadFile(t.Payloads.File)
			if err != nil {
				return nil, fmt.Errorf("template %s: payload file: %w", t.ID, err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					t.Payloads.List = append(t.Payloads.List, line)
				}
			}
		}
	}
	return &Engine{templates: tpls}, nil
}

// Count returns the number of loaded templates.
func (e *Engine) Count() int { return len(e.templates) }

// severityFor maps a template severity string to scanner.Severity safely.
func severityFor(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}

func (e *Engine) placeholder(t *Template) string {
	if t.Placeholder == "" {
		return "{{payload}}"
	}
	return t.Placeholder
}

// substitute replaces the placeholder in a template string value.
func substitute(s, placeholder, payload string) string {
	return strings.ReplaceAll(s, placeholder, payload)
}

// match evaluates all matchers of a template against a response, honoring
// the condition (and/or).
func (e *Engine) match(t *Template, resp *http.Response, body string) bool {
	if len(t.Matchers) == 0 {
		return false
	}

	and := t.Condition != ConditionOR
	result := and // identity element per condition

	for _, m := range t.Matchers {
		var ok bool
		switch m.Type {
		case MatchStatus:
			for _, code := range strings.Split(m.Value, ",") {
				code = strings.TrimSpace(code)
				if fmt.Sprintf("%d", resp.StatusCode) == code {
					ok = true
					break
				}
			}
		case MatchContains:
			needle := m.Value
			hay := body
			if !m.CaseSensitive {
				needle = strings.ToLower(needle)
				hay = strings.ToLower(hay)
			}
			ok = strings.Contains(hay, needle)
		case MatchRegex:
			re, err := regexp.Compile(m.Value)
			if err == nil {
				ok = re.MatchString(body)
			}
		case MatchHeader:
			h := resp.Header.Get(m.Header)
			if m.CaseSensitive {
				ok = strings.Contains(h, m.Value)
			} else {
				ok = strings.Contains(strings.ToLower(h), strings.ToLower(m.Value))
			}
		case MatchWordCount:
			lo, hi, valid := parseRange(m.Value)
			if valid {
				words := len(strings.Fields(body))
				ok = words >= lo && words <= hi
			}
		}

		if and {
			result = result && ok
			if !result {
				return false
			}
		} else {
			result = result || ok
			if result {
				return true
			}
		}
	}
	return result
}

// Run executes all templates against the target (level-gated).
func (e *Engine) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
	if len(e.templates) == 0 {
		return nil
	}

	httpCfg := utils.DefaultHTTPConfig()
	httpCfg.UserAgent = cfg.UserAgent
	httpCfg.Timeout = time.Duration(cfg.Timeout) * time.Second
	httpCfg.RateLimit = 0

	if cfg.SSLBypass {
		httpCfg.SkipVerify = true
	}

	client, err := utils.BuildHTTPClient(httpCfg)
	if err != nil {
		return fmt.Errorf("template: build client: %w", err)
	}
	e.httpCfg = httpCfg

	target := utils.NormalizeTarget(cfg.Target)

	limiter := delay.FromConfig(cfg.RateLimit, cfg.DelayStrategy, cfg.MaxDelayMs)

	for _, t := range e.templates {
		minLevel := scanner.ScanLevel(t.Level)
		if minLevel == 0 {
			minLevel = scanner.Level2
		}
		if cfg.Level < minLevel {
			continue
		}
		if len(t.Payloads.List) == 0 {
			// single-request template
			e.execute(cfg, t, target, "", limiter, findings)
			continue
		}
		for _, p := range t.Payloads.List {
			e.execute(cfg, t, target, p, limiter, findings)
		}
	}
	return nil
}

func (e *Engine) execute(cfg scanner.ScanConfig, t *Template, target, payload string, limiter *delay.Limiter, findings chan<- scanner.Finding) {
	full := strings.TrimRight(target, "/") + t.Endpoint

	method := strings.ToUpper(t.Method)
	if method == "" {
		method = http.MethodGet
	}

	var reqBody io.Reader
	var contentType string
	ph := e.placeholder(t)

	if t.Body != "" {
		ct := "application/x-www-form-urlencoded"
		body := substitute(t.Body, ph, payload)
		reqBody = strings.NewReader(body)
		contentType = "application/x-www-form-urlencoded"
		_ = ct
	}

	var reqURL string
	if len(t.Params) > 0 {
		u, err := url.Parse(full)
		if err != nil {
			return
		}
		q := u.Query()
		for k, v := range t.Params {
			q.Set(k, substitute(v, ph, payload))
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	} else {
		reqURL = full
	}

	resp, err := utils.DoRequest(client, method, reqURL, reqBody, e.httpCfg)
	if err != nil {
		utils.LogDebug(cfg.Verbose, "template %s: request failed: %v", t.ID, err)
		return
	}
	defer utils.SafeClose(resp.Body)

	if cfg.AdaptiveDelay {
		limiter.RecordStatusCode(resp.StatusCode)
	}
	if cfg.RateLimit > 0 {
		limiter.Wait()
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return
	}
	body := string(bodyBytes)

	if e.match(t, resp, body) {
		emitTemplateFinding(cfg, findings, t, target, reqURL, payload, body)
	}
}

func emitFinding(cfg scanner.ScanConfig, findings chan<- scanner.Finding, t *Template, target, reqURL, payload, body string) {
	findings <- scanner.Finding{
		ID:          fmt.Sprintf("tpl-%s", t.ID),
		Module:      "TEMPLATE",
		Type:        scanner.FindingVulnerability,
		Title:       fmt.Sprintf("%s [%s]", t.Name, t.ID),
		Description: t.Description,
		Severity:    severityFor(t.Severity),
		Confidence:  scanner.ConfidenceSuspected,
		Endpoint:    reqURL,
		Method:      strings.ToUpper(t.Method),
		Evidence:    fmt.Sprintf("template=%s payload=%q matched", t.ID, payload),
		CVSSScore:   t.CVSS,
		OWASPMapping: t.OWASP,
		Remediation: t.Remediation,
		References:  []string{t.Reference},
		Metadata:    map[string]string{"template": t.ID},
		DiscoveredAt: time.Now(),
	}
}
