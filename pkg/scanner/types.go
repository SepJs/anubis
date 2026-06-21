// Package scanner defines the core types and interfaces for the Anubis scan engine.
package scanner

import (
	"context"
	"time"
)

// ScanLevel controls how aggressively modules run.
type ScanLevel int

const (
	Level1 ScanLevel = 1 // passive recon, 5-min limit
	Level2 ScanLevel = 2 // active scanning
	Level3 ScanLevel = 3 // deep / comprehensive
)

// Severity represents how critical a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence indicates how certain we are about a finding.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceSuspected Confidence = "suspected"
	ConfidenceUnlikely  Confidence = "unlikely"
)

// FindingType classifies the nature of a finding.
type FindingType string

const (
	FindingVulnerability    FindingType = "vulnerability"
	FindingWeakness         FindingType = "weakness"
	FindingMisconfiguration FindingType = "misconfiguration"
	FindingInformational    FindingType = "informational"
)

// Finding represents a single discovered issue.
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
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

// ModuleResult holds the execution output of a single module run.
type ModuleResult struct {
	ModuleName string        `json:"module_name"`
	Status     string        `json:"status"` // completed | failed | timeout | skipped
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Findings   []Finding     `json:"findings"`
	Error      string        `json:"error,omitempty"`
}

// ScanConfig holds all runtime parameters for a scan.
// Populated from CLI flags in cmd/anubis/scan.go's buildConfig().
type ScanConfig struct {
	// Core
	Target  string
	Level   ScanLevel
	Modules []string
	DisabledModules []string

	// Output
	OutputFormat string
	OutputFile   string
	ReportLevel  string

	// Connection
	Timeout   int
	Threads   int
	RateLimit int
	UserAgent string
	ProxyURL  string
	ProxyAuth string
	CACert    string
	SSLBypass bool

	// Rate limiting strategy
	DelayStrategy string
	MaxDelayMs    int
	AdaptiveDelay bool

	// Auth
	Username     string
	Password     string
	Wordlist     string
	PayloadFile  string
	AuthStrategy string

	// Protocol scope
	Protocols []string

	// Behavior toggles
	Verbose              bool
	RespectLimits        bool
	QuickVuln            bool
	DeepScan             bool
	FrameworkMap         bool
	FrameworkExamples    string
	MaxFrameworkExamples int
	ShowRemediation      string
	BaselineFile         string
	ShowBaselineProgress bool
	ModulePriority       string

	// Batch / resume
	Batch     bool
	BatchFile string
	Resume    bool

	// Feature flags
	ExternalAPI bool
	JSSupport   bool
}

// ScanResult is the aggregated output of a complete scan.
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

// ScanSummary contains aggregated statistics about a completed scan.
type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByType           map[string]int `json:"by_type"`
	ByConfidence     map[string]int `json:"by_confidence"`
	ModulesRun       int            `json:"modules_run"`
	ModulesCompleted int            `json:"modules_completed"`
	ModulesFailed    int            `json:"modules_failed"`
}

// Module is the interface every scan module must implement.
// Run must respect ctx cancellation — check ctx.Done() inside loops.
// All findings must be sent via the findings channel, never returned.
type Module interface {
	Name() string
	Description() string
	Level() ScanLevel
	Run(cfg ScanConfig, findings chan<- Finding) error
}

// ContextModule is an optional interface for modules that want direct access
// to the parent context for finer-grained cancellation control.
// The engine checks for this interface and calls RunWithContext when present.
type ContextModule interface {
	Module
	RunWithContext(ctx context.Context, cfg ScanConfig, findings chan<- Finding) error
}
