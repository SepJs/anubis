package scanner

import (
	"time"
	"github.com/innervoid/anubis/pkg/requester"
)

// ScanLevel represents the aggressiveness of the scan
type ScanLevel int

const (
	Level1 ScanLevel = 1
	Level2 ScanLevel = 2
	Level3 ScanLevel = 3
)

// Severity represents finding severity
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents how confident we are in a finding
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceSuspected Confidence = "suspected"
	ConfidenceUnlikely  Confidence = "unlikely"
)

// FindingType classifies the nature of the finding
type FindingType string

const (
	FindingVulnerability    FindingType = "vulnerability"
	FindingWeakness         FindingType = "weakness"
	FindingMisconfiguration FindingType = "misconfiguration"
	FindingInformational    FindingType = "informational"
)

// Finding represents a single discovered issue
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

// ModuleResult holds the output of a single module run
type ModuleResult struct {
	ModuleName string        `json:"module_name"`
	Status     string        `json:"status"` // completed, skipped, failed, partial
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Findings   []Finding     `json:"findings"`
	Error      string        `json:"error,omitempty"`
}

// ScanConfig holds all runtime configuration for a scan
type ScanConfig struct {
	Target          string
	Level           ScanLevel
	Modules         []string
	DisabledModules []string
	OutputFormat    string
	OutputFile      string
	ReportLevel     string
	Timeout         int
	Threads         int
	RateLimit       int
	UserAgent       string
	ProxyURL        string
	ProxyAuth       string
	CACert          string
	Username        string
	Password        string
	Wordlist        string
	PayloadFile     string
	AuthStrategy    string
	Protocols       []string
	Verbose         bool
	RespectLimits   bool
	QuickVuln       bool
	DeepScan        bool
	FrameworkMap    bool
	FrameworkExamples  string
	MaxFrameworkExamples int
	ShowRemediation string
	BaselineFile    string
	ShowBaselineProgress bool
	ModulePriority  string
	Batch           bool
	BatchFile       string
	Resume          bool
	ExternalAPI     bool
	SSLBypass       bool
	JSSupport       bool
}

// ScanResult holds the complete output of a scan
type ScanResult struct {
	Target       string          `json:"target"`
	ScanLevel    ScanLevel       `json:"scan_level"`
	StartTime    time.Time       `json:"start_time"`
	EndTime      time.Time       `json:"end_time"`
	Duration     time.Duration   `json:"duration"`
	Modules      []ModuleResult  `json:"modules"`
	AllFindings  []Finding       `json:"all_findings"`
	Summary      ScanSummary     `json:"summary"`
	BaselineData interface{}     `json:"baseline_data,omitempty"`
}

// ScanSummary is the stats section of a report
type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByType           map[string]int `json:"by_type"`
	ByConfidence     map[string]int `json:"by_confidence"`
	ModulesRun       int            `json:"modules_run"`
	ModulesCompleted int            `json:"modules_completed"`
	ModulesFailed    int            `json:"modules_failed"`
}

// Module is the interface every scan module must implement
type Module interface {
	Name() string
	Description() string
	Level() ScanLevel
	Run(cfg ScanConfig, findings chan<- Finding, client *requester.AnubisClient) error 
}
