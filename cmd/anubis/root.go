package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
	"github.com/spf13/cobra"
)

var (
	// Target / level
	target string
	level  int

	// Module control
	modules         []string
	disabledModules []string

	// Output
	outputFormat string
	outputFile   string
	reportLevel  string

	// Connection
	timeout   int
	threads   int
	rateLimit int
	userAgent string
	proxyURL  string
	proxyAuth string
	caCert    string
	sslBypass bool

	// Auth
	username     string
	password     string
	wordlist     string
	payloadFile  string
	authStrategy string

	// Protocols
	protocols []string

	// Behavior
	verbose              bool
	respectLimits        bool
	quickVuln            bool
	deepScan             bool
	frameworkMap         bool
	frameworkExamples    string
	maxFrameworkExamples int
	showRemediation      string
	baselineFile         string
	showBaselineProgress bool
	modulePriority       string

	// Batch
	batch     bool
	batchFile string

	// Resume
	resume bool

	// Feature flags
	externalAPI bool
	jsSupport   bool

	// Update flags
	checkUpdate  bool
	doUpdate     bool
	showVersion  bool

	// Delay / rate-limit strategy flags
	delayStrategy  string
	maxDelayMs     int
	adaptiveDelay  bool
)

var rootCmd = &cobra.Command{
	Use:   "anubis [flags] -t TARGET",
	Short: "Anubis — Modular Security Scanner",
	Long: `
Anubis is a modular web application security scanner.
Designed for authorized penetration testing and security assessments.

Scan levels:
  1 — Light passive reconnaissance (safe, quick, 5-min time limit)
  2 — Active scanning (moderate intensity)
  3 — Deep scan (aggressive, comprehensive)

Example usage:
  anubis -t https://example.com -l 1
  anubis -t https://example.com -l 2 --format html+json -o report
  anubis -t https://example.com -l 3 --threads 10 --deep-scan
  anubis -t https://example.com -l 2 --proxy http://127.0.0.1:8080
  anubis --resume
  anubis --batch --batch-file targets.txt -l 1
`,
	Args: cobra.NoArgs,
	RunE: runScan,
}

func init() {
	// Target
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or IP address")
	rootCmd.Flags().IntVarP(&level, "level", "l", 1, "Scan level: 1 (light), 2 (active), 3 (deep)")

	// Module control
	rootCmd.Flags().StringSliceVarP(&modules, "modules", "m", nil, "Modules to run (comma-separated, default: all eligible for level)")
	rootCmd.Flags().StringSliceVar(&disabledModules, "disable-modules", nil, "Modules to skip (comma-separated)")

	// Output
	rootCmd.Flags().StringVar(&outputFormat, "format", "html+json", "Output format(s): json, html, csv (combine with +)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file base name (default: anubis_report_<timestamp>)")
	rootCmd.Flags().StringVar(&reportLevel, "report-level", "comprehensive", "Report detail: basic, detailed, comprehensive")

	// Connection
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout (seconds)")
	rootCmd.Flags().IntVar(&threads, "threads", 5, "Concurrent worker threads")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 150, "Delay between requests (milliseconds)")
	rootCmd.Flags().StringVar(&userAgent, "user-agent", "Mozilla/5.0 (compatible; Anubis-Scanner/1.0; Security-Testing)", "Custom User-Agent string")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&proxyAuth, "proxy-auth", "", "Proxy credentials in user:pass format")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate")
	rootCmd.Flags().BoolVar(&sslBypass, "ssl-bypass", false, "Bypass SSL/TLS certificate validation")

	// Auth
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Username for authenticated scanning")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "Password for authenticated scanning")
	rootCmd.Flags().StringVar(&wordlist, "wordlist", "", "Wordlist file for brute-force")
	rootCmd.Flags().StringVar(&payloadFile, "payload-file", "", "Custom payload file")
	rootCmd.Flags().StringVar(&authStrategy, "auth-strategy", "defaults", "Auth strategy: none, defaults, bruteforce, combined")

	// Protocols
	rootCmd.Flags().StringSliceVar(&protocols, "protocols", []string{"http", "https"}, "Protocols: http, https, ftp, smtp")

	// Behavior
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.Flags().BoolVar(&respectLimits, "respect-limits", false, "Respect robots.txt and crawl delays")
	rootCmd.Flags().BoolVar(&quickVuln, "quick-vuln", false, "Stop each module on first finding")
	rootCmd.Flags().BoolVar(&deepScan, "deep-scan", false, "More thorough scanning (slower)")
	rootCmd.Flags().BoolVar(&frameworkMap, "framework-map", false, "Map findings to OWASP/CIS frameworks")
	rootCmd.Flags().StringVar(&frameworkExamples, "framework-examples", "", "Show framework code examples: owasp, cis, both")
	rootCmd.Flags().IntVar(&maxFrameworkExamples, "max-framework-examples", 3, "Max code examples to include")
	rootCmd.Flags().StringVar(&showRemediation, "show-remediation", "all", "Show remediation for: all, high, critical, none")
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to saved baseline file for comparison")
	rootCmd.Flags().BoolVar(&showBaselineProgress, "show-baseline-progress", true, "Show baseline progress bar")
	rootCmd.Flags().StringVar(&modulePriority, "module-priority", "severity", "Module priority: severity, speed, comprehensive")

	// Batch
	rootCmd.Flags().BoolVar(&batch, "batch", false, "Batch mode — scan multiple targets")
	rootCmd.Flags().StringVar(&batchFile, "batch-file", "", "File with targets (one per line) for batch mode")

	// Resume
	rootCmd.Flags().BoolVar(&resume, "resume", false, "Resume from last checkpoint")

	// Feature flags
	rootCmd.Flags().BoolVar(&externalAPI, "external-api", false, "Enable external API integrations (Shodan, VirusTotal)")
	rootCmd.Flags().BoolVar(&jsSupport, "js-support", false, "Enable JavaScript rendering (requires headless browser)")

	// Update
	rootCmd.Flags().BoolVar(&checkUpdate, "check-update", false, "Check GitHub for a newer release and exit (no scan, no download)")
	rootCmd.Flags().BoolVar(&doUpdate, "update", false, "Download and install the latest release in place, then exit")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Print version information and exit")

	// Delay / rate-limit strategy
	rootCmd.Flags().StringVar(&delayStrategy, "strategy", "jitter", "Delay strategy: fixed, exponential, linear, jitter")
	rootCmd.Flags().IntVar(&maxDelayMs, "max-delay", 60000, "Maximum delay between requests in milliseconds (caps backoff growth)")
	rootCmd.Flags().BoolVar(&adaptiveDelay, "adaptive-delay", false, "Auto-adjust delay based on target responses (slows down on 429/503, speeds up when clean)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// --version: print and exit immediately, no banner, no disclaimer —
	// scripts piping this output shouldn't have to filter out decoration.
	if showVersion {
		fmt.Println(version.Info())
		return nil
	}

	// --check-update and --update both short-circuit before any scan setup.
	// Neither requires --target, so these checks happen before that validation.
	if checkUpdate {
		return runCheckUpdate()
	}
	if doUpdate {
		return runUpdate()
	}

	utils.PrintBanner()
	utils.PrintDisclaimer()

	// Validate level
	if level < 1 || level > 3 {
		return fmt.Errorf("scan level must be 1, 2, or 3 (got %d)", level)
	}

	// Target required unless resuming
	if target == "" && !resume && !batch {
		return fmt.Errorf("target is required: use -t https://example.com")
	}

	// Batch requires a file
	if batch && batchFile == "" {
		return fmt.Errorf("--batch requires --batch-file <path>")
	}

	// Validate format
	for _, f := range strings.Split(outputFormat, "+") {
		f = strings.TrimSpace(f)
		switch f {
		case "json", "html", "csv":
		default:
			return fmt.Errorf("invalid format %q — valid: json, html, csv (combine with +)", f)
		}
	}

	// Validate delay strategy
	switch delayStrategy {
	case "fixed", "exponential", "linear", "jitter":
	default:
		return fmt.Errorf("invalid --strategy %q — valid: fixed, exponential, linear, jitter", delayStrategy)
	}

	// SSL bypass warning
	if sslBypass {
		color.Yellow("[!] SSL bypass enabled — certificate validation disabled")
	}

	return dispatchScan()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
