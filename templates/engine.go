package templates

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/delay"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/utils"
)

// maxTemplatePayloads caps payloads per template to bound scan time.
const maxTemplatePayloads = 200

// bodyCap limits how many response bytes are read per request.
const bodyCap = 128 * 1024

// Engine executes loaded templates against a target.
type Engine struct {
	templates []*Template
}

// NewEngine loads templates from dir. Directory errors are fatal (returned),
// per-file validation errors are logged and skipped.
func NewEngine(dir string) (*Engine, error) {
	if dir == "" {
		return &Engine{}, nil
	}
	if _, err := osStat(dir); err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	tpls, errs := LoadDir(dir)
	for _, err := range errs {
		utils.LogWarn("%v", err)
	}
	return &Engine{templates: tpls}, nil
}

// Templates returns the loaded templates.
func (e *Engine) Templates() []*Template { return e.templates }

// Count returns the number of loaded templates.
func (e *Engine) Count() int { return len(e.templates) }

// placeholder returns the substitution token for a template.
func placeholder(t *Template) string {
	if t.Placeholder == "" {
		return "{{payload}}"
	}
	return t.Placeholder
}

func substitute(s, ph, payload string) string {
	if ph == "" {
		return s
	}
	return strings.ReplaceAll(s, ph, payload)
}

// match evaluates all matchers with the template's condition.
func match(t *Template, resp *http.Response, body string) bool {
	if len(t.Matchers) == 0 {
		return false
	}
	isAnd := t.Condition != ConditionOr
	matched := isAnd // identity element

	for i, m := range t.Matchers {
		ok := evalMatcher(t, i, m, resp, body)
		if isAnd {
			matched = matched && ok
			if !matched {
				return false
			}
		} else {
			matched = matched || ok
			if matched {
				return true
			}
		}
	}
	return matched
}

func evalMatcher(t *Template, idx int, m Matcher, resp *http.Response, body string) bool {
	switch m.Type {
	case MatchStatus:
		for _, code := range strings.Split(m.Value, ",") {
			code = strings.TrimSpace(code)
			if code == strconv.Itoa(resp.StatusCode) {
				return true
			}
		}
		return false
	case MatchContains:
		needle, hay := m.Value, body
		if !m.CaseSensitive {
			needle, hay = strings.ToLower(needle), strings.ToLower(hay)
		}
		return strings.Contains(hay, needle)
	case MatchRegex:
		re, err := regexp.Compile(m.Value)
		if err != nil {
			return false
		}
		return re.MatchString(body)
	case MatchHeader:
		h := resp.Header.Get(m.Header)
		if m.CaseSensitive {
			return strings.Contains(h, m.Value)
		}
		return strings.Contains(strings.ToLower(h), strings.ToLower(m.Value))
	case MatchWordCount:
		lo, hi, ok := parseRange(m.Value)
		if !ok {
			return false
		}
		n := len(strings.Fields(body))
		return n >= lo && n <= hi
	default:
		return false
	}
}

// severityFor maps template severity strings to scanner severities (fail-low).
func severityFor(s string) scanner.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
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

// Run executes all level-eligible templates against the target.
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

		payloads := t.Payloads.List
		if len(payloads) == 0 && t.Payloads.File != "" {
			payloads = utils.LoadWordlist(t.Payloads.File, nil)
		}
		if len(payloads) > maxTemplatePayloads {
			payloads = payloads[:maxTemplatePayloads]
		}

		if len(payloads) == 0 {
			e.execute(cfg, client, httpCfg, t, target, "", limiter)
			continue
		}
		for _, p := range payloads {
			e.execute(cfg, client, httpCfg, t, target, p, limiter)
		}
	}
	return nil
}

func (e *Engine) execute(
	cfg scanner.ScanConfig,
	client *http.Client,
	httpCfg utils.HTTPConfig,
	t *Template,
	target string,
	payload string,
	limiter *delay.Limiter,
) {
	ph := placeholder(t)
	full := strings.TrimRight(target, "/") + t.Endpoint

	method := strings.ToUpper(t.Method)
	if method == "" {
		method = http.MethodGet
	}

	var reqURL string
	var reqBody io.Reader

	if t.Body != "" {
		// POST-style: body may carry the payload placeholder
		reqURL = full
		reqBody = strings.NewReader(substitute(t.Body, ph, payload))
	} else {
		// GET with (optionally templated) query params
		u, err := urlParse(full)
		if err != nil {
			utils.LogDebug(cfg.Verbose, "template %s: parse url: %v", t.ID, err)
			return
		}
		q := u.Query()
		for k, v := range t.Params {
			q.Set(k, substitute(v, ph, payload))
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	var resp *http.Response
	var err error

	if reqBody != nil {
		req, rerr := http.NewRequest(method, reqURL, reqBody)
		if rerr != nil {
			utils.LogDebug(cfg.Verbose, "template %s: build request: %v", t.ID, rerr)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if httpCfg.UserAgent != "" {
			req.Header.Set("User-Agent", httpCfg.UserAgent)
		}
		resp, err := client.Do(req)
		if err != nil {
			utils.LogDebug(cfg.Verbose, "template %s: request failed: %v", t.ID, err)
			return
		}
		defer utils.SafeClose(resp.Body)
		recordWait(cfg, limiter, resp.StatusCode)

		body, err := io.ReadAll(io.LimitReader(resp.Body, bodyCap))
		if err != nil {
			return
		}
		if match(t, resp, string(body)) {
			emitFinding(t, reqURL, payload)
		}
		return
	}

	resp, err := utils.DoRequest(client, method, reqURL, nil, httpCfg)
	if err != nil {
		utils.LogDebug(cfg.Verbose, "template %s: request failed: %v", t.ID, err)
		return
	}
	defer utils.SafeClose(resp.Body)
	recordWait(cfg, limiter, resp.StatusCode)

	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyCap))
	if err != nil {
		return
	}

	if match(t, resp, string(body)) {
		emitFinding(t, reqURL, payload)
	}
}

func recordWait(cfg scanner.ScanConfig, limiter *delay.Limiter, status int) {
	if cfg.AdaptiveDelay && status > 0 {
		limiter.RecordStatusCode(status)
	}
	if cfg.RateLimit > 0 {
		limiter.Wait()
	}
}

func emitFinding(t *Template, reqURL, payload string) {
	findings <- scanner.Finding{
		ID:          fmt.Sprintf("tpl-%s", t.ID),
		Module:      "TEMPLATE",
		Type:        scanner.FindingVulnerability,
		Title:       fmt.Sprintf("%s [%s]", t.Name, t.ID),
		Description: t.Description,
		Severity:    severityFor(t.Severity),
		Confidence:  scanner.ConfidenceSuspected,
		Endpoint:    reqURL,
		Method:      methodOf(t),
		Evidence:    fmt.Sprintf("template=%s payload=%q", t.ID, payload),
		CVSSScore:   t.CVSS,
		OWASPMapping: t.OWASP,
		Remediation: t.Remediation,
		References:  refs(t),
		Metadata:    map[string]string{"template": t.ID},
		DiscoveredAt: time.Now(),
	}
}

func regexpCompile(s string) (*regexp.Regexp, error) { return regexp.Compile(s) }
func osStat(path string) (os.FileInfo, error)        { return os.Stat(path) }
func strconvAtoi(s string) (int, error)              { return strconv.Atoi(s) }
func methodOf(t *Template) string {
	if t.Method == "" {
		return "GET"
	}
	return strings.ToUpper(t.Method)
}
func refs(t *Template) []string {
	if t.Reference == "" {
		return nil
	}
	return []string{t.Reference}
}
