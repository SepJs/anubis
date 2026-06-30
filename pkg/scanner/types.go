package scanner

import (
	"context"
	"sync/atomic"
	"time"
)

type ScanLevel int

const (
	Level1 ScanLevel = 1
	Level2 ScanLevel = 2
	Level3 ScanLevel = 3
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceSuspected Confidence = "suspected"
	ConfidenceUnlikely  Confidence = "unlikely"
)

type FindingType string

const (
	FindingVulnerability    FindingType = "vulnerability"
	FindingWeakness         FindingType = "weakness"
	FindingMisconfiguration FindingType = "misconfiguration"
	FindingInformational    FindingType = "informational"
)

type Finding struct {
	ID           string            `json:"id"`
	Module       string            `json:"module"`
	Type         FindingType       `json:"type"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Severity     Severity          `json:"severity"`
	Confidence   Confidence        `json:"confidence"`
	Endpoint     string            `json:"endpoint,omitempty"`
	Parameter    string            `json:"parameter,omitempty"`
	Method       string            `json:"method,omitempty"`
	Evidence     string            `json:"evidence,omitempty"`
	Remediation  string            `json:"remediation,omitempty"`
	VulnCode     string            `json:"vuln_code,omitempty"`
	SecureCode   string            `json:"secure_code,omitempty"`
	References   []string          `json:"references,omitempty"`
	OWASPMapping string            `json:"owasp_mapping,omitempty"`
	CVSSScore    float64           `json:"cvss_score,omitempty"`
	Likelihood   string            `json:"likelihood,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

type ModuleResult struct {
	ModuleName string        `json:"module_name"`
	Status     string        `json:"status"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Findings   []Finding     `json:"findings"`
	Error      string        `json:"error,omitempty"`
}

type ScanConfig struct {
	Target          string   `yaml:"target"`
	Level           ScanLevel `yaml:"level"`
	Modules         []string  `yaml:"modules,omitempty"`
	DisabledModules []string  `yaml:"disabled_modules,omitempty"`

	OutputFormat string `yaml:"output_format"`
	OutputFile   string `yaml:"output_file,omitempty"`
	ReportLevel  string `yaml:"report_level"`

	Timeout    int    `yaml:"timeout"`
	Threads    int    `yaml:"threads"`
	RateLimit  int    `yaml:"rate_limit"`
	UserAgent  string `yaml:"user_agent,omitempty"`
	ProxyURL   string `yaml:"proxy_url,omitempty"`
	ProxyAuth  string `yaml:"proxy_auth,omitempty"`
	CACert     string `yaml:"ca_cert,omitempty"`
	SSLBypass  bool   `yaml:"ssl_bypass"`

	DelayStrategy string `yaml:"delay_strategy"`
	MaxDelayMs    int    `yaml:"max_delay_ms"`
	AdaptiveDelay bool   `yaml:"adaptive_delay"`

	Username     string `yaml:"username,omitempty"`
	Password     string `yaml:"password,omitempty"`
	Wordlist     string `yaml:"wordlist,omitempty"`
	PayloadFile  string `yaml:"payload_file,omitempty"`
	AuthStrategy string `yaml:"auth_strategy"`

	Protocols []string `yaml:"protocols"`

	Verbose              bool   `yaml:"verbose"`
	RespectLimits        bool   `yaml:"respect_limits"`
	QuickVuln            bool   `yaml:"quick_vuln"`
	DeepScan             bool   `yaml:"deep_scan"`
	GhostMode            bool   `yaml:"ghost_mode"`
	FrameworkMap         bool   `yaml:"framework_map"`
	FrameworkExamples    string `yaml:"framework_examples,omitempty"`
	MaxFrameworkExamples int    `yaml:"max_framework_examples"`
	ShowRemediation      string `yaml:"show_remediation"`
	BaselineFile         string `yaml:"baseline_file,omitempty"`
	ShowBaselineProgress bool   `yaml:"show_baseline_progress"`
	ModulePriority       string `yaml:"module_priority"`

	Batch     bool   `yaml:"batch"`
	BatchFile string `yaml:"batch_file,omitempty"`
	Resume    bool   `yaml:"resume"`

	ExternalAPI bool `yaml:"external_api"`
	JSSupport   bool `yaml:"js_support"`
}

type ScanResult struct {
	Target      string         `json:"target"`
	ScanLevel   ScanLevel      `json:"scan_level"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time"`
	Duration    time.Duration  `json:"duration"`
	Modules     []ModuleResult `json:"modules"`
	AllFindings []Finding      `json:"all_findings"`
	Summary     ScanSummary    `json:"summary"`
	BaselineData interface{}   `json:"baseline_data,omitempty"`
}

type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByType           map[string]int `json:"by_type"`
	ByConfidence     map[string]int `json:"by_confidence"`
	ModulesRun       int            `json:"modules_run"`
	ModulesCompleted int            `json:"modules_completed"`
	ModulesFailed    int            `json:"modules_failed"`
	CVSSAverage      float64        `json:"cvss_average"`
	RiskScore        float64        `json:"risk_score"`
}

type Result[T any] struct {
	Value T
	Err   error
}

type AtomicResult struct {
	ptr atomic.Pointer[ScanResult]
}

func NewAtomicResult() *AtomicResult {
	return &AtomicResult{}
}

func (a *AtomicResult) Load() *ScanResult {
	return a.ptr.Load()
}

func (a *AtomicResult) Store(r *ScanResult) {
	a.ptr.Store(r)
}

type Module interface {
	Name() string
	Description() string
	Level() ScanLevel
	Run(cfg ScanConfig, findings chan<- Finding) error
}

type ContextModule interface {
	Module
	RunWithContext(ctx context.Context, cfg ScanConfig, findings chan<- Finding) error
}

type HeuristicModule interface {
	Module
	Likelihood() float64
	SeverityScore() float64
}
