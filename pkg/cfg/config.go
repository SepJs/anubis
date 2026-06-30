package cfg

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/SepJs/anubis/pkg/scanner"
)

type Config struct {
	Version  string         `yaml:"version"`
	Scan     ScanConfig     `yaml:"scan"`
	Evasion  EvasionConfig  `yaml:"evasion"`
	Proxy    ProxyConfig    `yaml:"proxy"`
	Database DatabaseConfig `yaml:"database"`
	API      APIConfig      `yaml:"api"`
	Logging  LoggingConfig  `yaml:"logging"`
	Profiles []ScanProfile  `yaml:"profiles"`
}

type ScanConfig struct {
	DefaultLevel    int      `yaml:"default_level"`
	DefaultThreads  int      `yaml:"default_threads"`
	DefaultTimeout  int      `yaml:"default_timeout"`
	DelayStrategy   string   `yaml:"delay_strategy"`
	RateLimit       int      `yaml:"rate_limit"`
	MaxDelayMs      int      `yaml:"max_delay_ms"`
	AdaptiveDelay   bool     `yaml:"adaptive_delay"`
	OutputFormat    string   `yaml:"output_format"`
	ReportLevel     string   `yaml:"report_level"`
	DefaultModules  []string `yaml:"default_modules"`
	DisabledModules []string `yaml:"disabled_modules"`
}

type EvasionConfig struct {
	JitterEnabled     bool    `yaml:"jitter_enabled"`
	JitterVariance    float64 `yaml:"jitter_variance"`
	UserAgentRotate   bool    `yaml:"user_agent_rotate"`
	FingerprintMimic  string  `yaml:"fingerprint_mimic"`
	PacketPadding     bool    `yaml:"packet_padding"`
	MinPaddingBytes   int     `yaml:"min_padding_bytes"`
	MaxPaddingBytes   int     `yaml:"max_padding_bytes"`
	GhostMode         bool    `yaml:"ghost_mode"`
	AntiSandboxDetect bool    `yaml:"anti_sandbox_detect"`
}

type ProxyConfig struct {
	Enabled     bool     `yaml:"enabled"`
	RotateEvery int      `yaml:"rotate_every"`
	Proxies     []string `yaml:"proxies"`
	HealthCheck bool     `yaml:"health_check"`
	MaxFails    int      `yaml:"max_fails"`
}

type DatabaseConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Path     string `yaml:"path"`
	Encrypt  bool   `yaml:"encrypt"`
	Passkey  string `yaml:"passkey"`
}

type APIConfig struct {
	Enabled      bool   `yaml:"enabled"`
	GRPCListen   string `yaml:"grpc_listen"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	AuthToken    string `yaml:"auth_token"`
}

type LoggingConfig struct {
	Level     string `yaml:"level"`
	File      string `yaml:"file"`
	JSON      bool   `yaml:"json"`
	CrashLog  string `yaml:"crash_log"`
}

type ScanProfile struct {
	Name    string            `yaml:"name"`
	Config  scanner.ScanConfig `yaml:"config"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: "1.0",
		Scan: ScanConfig{
			DefaultLevel:   2,
			DefaultThreads: 10,
			DefaultTimeout: 30,
			DelayStrategy:  "jitter",
			RateLimit:      150,
			MaxDelayMs:     60000,
			AdaptiveDelay:  true,
			OutputFormat:   "html+json",
			ReportLevel:    "comprehensive",
		},
		Evasion: EvasionConfig{
			JitterEnabled:     true,
			JitterVariance:    0.3,
			UserAgentRotate:   true,
			FingerprintMimic:  "random",
			PacketPadding:     true,
			MinPaddingBytes:   8,
			MaxPaddingBytes:   64,
			GhostMode:         false,
			AntiSandboxDetect: true,
		},
		Proxy: ProxyConfig{
			Enabled:     false,
			RotateEvery: 5,
			HealthCheck: true,
			MaxFails:    3,
		},
		Database: DatabaseConfig{
			Enabled: true,
			Path:    "anubis_history.db",
			Encrypt: false,
		},
		Logging: LoggingConfig{
			Level:    "info",
			File:     "anubis.log",
			JSON:     false,
			CrashLog: "crash.log",
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Config) Validate() error {
	if c.Scan.DefaultLevel < 1 || c.Scan.DefaultLevel > 3 {
		return fmt.Errorf("invalid scan level: %d", c.Scan.DefaultLevel)
	}
	if c.Scan.DefaultThreads < 1 {
		return fmt.Errorf("threads must be >= 1")
	}
	if c.Scan.RateLimit < 0 {
		return fmt.Errorf("rate limit must be >= 0")
	}
	validStrategies := map[string]bool{
		"fixed": true, "exponential": true, "linear": true,
		"jitter": true, "randomized": true, "polymorphic": true,
	}
	if !validStrategies[c.Scan.DelayStrategy] {
		return fmt.Errorf("invalid delay strategy: %s", c.Scan.DelayStrategy)
	}
	return nil
}

func (c *Config) ToScanConfig(target string, level int) scanner.ScanConfig {
	cfg := scanner.ScanConfig{
		Target:        target,
		Level:         scanner.ScanLevel(level),
		Threads:       c.Scan.DefaultThreads,
		Timeout:       c.Scan.DefaultTimeout,
		DelayStrategy: c.Scan.DelayStrategy,
		RateLimit:     c.Scan.RateLimit,
		MaxDelayMs:    c.Scan.MaxDelayMs,
		AdaptiveDelay: c.Scan.AdaptiveDelay,
		OutputFormat:  c.Scan.OutputFormat,
		ReportLevel:   c.Scan.ReportLevel,
		GhostMode:     c.Evasion.GhostMode,
	}
	return cfg
}
