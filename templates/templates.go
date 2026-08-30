// Package template implements a YAML-based custom check engine, similar in
// spirit to Nuclei templates: users define checks (id, matchers, payloads)
// in YAML files and Anubis executes them against targets without any Go code.
package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchType defines how matchers compare against the response.
type MatchType string

const (
	MatchContains  MatchType = "contains"  // substring match (case-insensitive)
	MatchRegex     MatchType = "regex"     // regex match on body
	MatchStatus    MatchType = "status"    // HTTP status code(s), comma-separated
	MatchHeader    MatchType = "header"    // header contains value (name:value)
	MatchWordCount MatchType = "words"     // word-count range, e.g. "120-180"
)

// Condition when multiple matchers are present.
type Condition string

const (
	ConditionAND Condition = "and"
	ConditionOR  Condition = "or"
)

// Matcher is a single response predicate.
type Matcher struct {
	Type   MatchType `yaml:"type"`
	Value  string    `yaml:"value"`
	Header string    `yaml:"header,omitempty"` // for type: header
	Part   string    `yaml:"part,omitempty"`   // body (default) or header
	CaseSensitive bool `yaml:"case_sensitive,omitempty"`
}

// Payload can be a fixed list or an external file.
type Payloads struct {
	File string    `yaml:"file,omitempty"` // path to wordlist-style payload file
	List []string  `yaml:"list,omitempty"` // inline payloads
}

// Template is a single custom check.
type Template struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description,omitempty"`
	Severity    string    `yaml:"severity"` // critical|high|medium|low|info
	Level       int       `yaml:"level"`    // min scan level (default 2)
	Reference   string    `yaml:"reference,omitempty"`
	Endpoint    string    `yaml:"endpoint"`            // path appended to target, e.g. /api/login
	Method      string    `yaml:"method"`              // GET/POST (default GET)
	Params      map[string]string `yaml:"params"`      // fixed query/body params
	Body        string    `yaml:"body,omitempty"`      // static POST body ({{payload}} placeholder)
	Placeholder string    `yaml:"placeholder"`         // default "{{payload}}"
	Payloads    Payloads  `yaml:"payloads"`
	Matchers    []Matcher `yaml:"matchers"`
	Condition   Condition `yaml:"condition"`           // and (default) | or
	CVSS        float64   `yaml:"cvss,omitempty"`
	OWASP       string    `yaml:"owasp,omitempty"`
	Remediation string    `yaml:"remediation,omitempty"`
}

// Validate checks a template for structural correctness.
func (t *Template) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("template: id is required")
	}
	if t.Endpoint == "" && t.Body == "" {
		return fmt.Errorf("template %s: endpoint is required for request-based checks", t.ID)
	}
	if len(t.Matchers) == 0 {
		return fmt.Errorf("template %s: at least one matcher is required", t.ID)
	}
	for i, m := range t.Matchers {
		switch m.Type {
		case MatchContains, MatchStatus, MatchRegex, MatchWordCount:
			if m.Value == "" && m.Type != MatchWordCount {
				return fmt.Errorf("template %s: matcher %d (type %s) requires value", t.ID, i, m.Type)
			}
			if m.Type == MatchWordCount {
				if _, ok := parseRange(m.Value); !ok {
					return fmt.Errorf("template %s: matcher %d: invalid words range %q (want \"min-max\")", t.ID, i, m.Value)
				}
			}
		case MatchHeader:
			if m.Header == "" || m.Value == "" {
				return fmt.Errorf("template %s: matcher %d: header matchers require header and value", t.ID, i)
			}
		default:
			return fmt.Errorf("template %s: matcher %d: unknown type %q", t.ID, i, m.Type)
		}
	}
	return nil
}

// LoadFile parses a single YAML template file.
func LoadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("template: read %s: %w", path, err)
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("template: parse %s: %w", path, err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// LoadDir loads every *.yml / *.yaml file in a directory (non-recursive).
// Returns templates plus a list of per-file errors (not fatal).
func LoadDir(dir string) ([]*Template, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("template: read dir %s: %w", dir, err)}
	}

	var out []*Template
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		t, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, t)
	}
	return out, errs
}

func parseRange(s string) (int, int, bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	var lo, hi int
	if _, err := fmt.Sscanf(parts[0], "%d", &lo); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &hi); err != nil {
		return 0, 0, false
	}
	return lo, hi, true
}
