// Package template implements a YAML-based custom check engine, in the
// spirit of Nuclei templates: users define checks (id, request, matchers,
// payloads) in YAML files and Anubis executes them without any Go changes.
package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchType defines how a matcher compares against the response.
type MatchType string

const (
	MatchContains MatchType = "contains" // substring match (case-insensitive by default)
	MatchRegex    MatchType = "regex"    // regexp match on body
	MatchStatus   MatchType = "status"   // HTTP status code(s), comma-separated
	MatchHeader   MatchType = "header"   // named header contains value
	MatchWordCount MatchType = "words"   // body word count within "min-max" range
)

// Condition combines multiple matchers.
type Condition string

const (
	ConditionAnd Condition = "and"
	ConditionOr  Condition = "or"
)

// Matcher is a single response predicate.
type Matcher struct {
	Type          MatchType `yaml:"type"`
	Value         string    `yaml:"value"`
	Header        string    `yaml:"header,omitempty"`
	CaseSensitive bool      `yaml:"case_sensitive,omitempty"`
}

// Payloads is either an inline list or an external file (one payload per line).
type Payloads struct {
	File string   `yaml:"file,omitempty"`
	List []string `yaml:"list,omitempty"`
}

// Template is a single YAML-defined custom check.
type Template struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Level       int               `yaml:"level,omitempty"`
	Endpoint    string            `yaml:"endpoint,omitempty"`
	Method      string            `yaml:"method,omitempty"`
	Params      map[string]string `yaml:"params,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	Placeholder string            `yaml:"placeholder,omitempty"`
	Payloads    Payloads          `yaml:"payloads,omitempty"`
	Matchers    []Matcher         `yaml:"matchers"`
	Condition   Condition         `yaml:"condition,omitempty"`
	CVSS        float64           `yaml:"cvss,omitempty"`
	OWASP       string            `yaml:"owasp,omitempty"`
	Remediation string            `yaml:"remediation,omitempty"`
	Reference   string            `yaml:"reference,omitempty"`
}

// Validate checks structural correctness.
func (t *Template) Validate() error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template: id is required")
	}
	if t.Endpoint == "" && t.Body == "" {
		return fmt.Errorf("template %q: endpoint is required", t.ID)
	}
	if len(t.Matchers) == 0 {
		return fmt.Errorf("template %q: at least one matcher is required", t.ID)
	}
	for i, m := range t.Matchers {
		switch m.Type {
		case MatchContains, MatchRegex:
			if m.Value == "" {
				return fmt.Errorf("template %q: matcher %d (type %s) requires value", t.ID, i, m.Type)
			}
			if m.Type == MatchRegex {
				if _, err := regexpCompile(m.Value); err != nil {
					return fmt.Errorf("template %q: matcher %d: invalid regex: %w", t.ID, i, err)
				}
			}
		case MatchStatus:
			if strings.TrimSpace(m.Value) == "" {
				return fmt.Errorf("template %q: matcher %d: status requires value", t.ID, i)
			}
		case MatchHeader:
			if m.Header == "" || m.Value == "" {
				return fmt.Errorf("template %q: matcher %d: header matchers require header and value", t.ID, i)
			}
		case MatchWordCount:
			if _, _, ok := parseRange(m.Value); !ok {
				return fmt.Errorf("template %q: matcher %d: invalid words range %q (want \"min-max\")", t.ID, i, m.Value)
			}
		default:
			return fmt.Errorf("template %q: matcher %d: unknown type %q", t.ID, i, m.Type)
		}
	}
	return nil
}

// LoadFile parses and validates a single YAML template file.
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

// LoadDir loads every *.yml / *.yaml file in dir. Per-file errors are
// returned separately and are non-fatal — a bad template never aborts a scan.
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
	parts := strings.SplitN(strings.TrimSpace(s), "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconvAtoi(parts[0])
	hi, err2 := strconvAtoi(parts[1])
	if err1 != nil || err2 != nil || lo < 0 || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}
