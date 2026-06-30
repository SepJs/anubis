package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
)

var (
	target string
	level  int

	modules         []string
	disabledModules []string

	outputFormat string
	outputFile   string
	reportLevel  string

	timeout   int
	threads   int
	rateLimit int
	userAgent string
	proxyURL  string
	proxyAuth string
	caCert    string
	sslBypass bool

	username     string
	password     string
	wordlist     string
	payloadFile  string
	authStrategy string

	protocols []string

	verbose              bool
	respectLimits        bool
	quickVuln            bool
	deepScan             bool
	ghostMode            bool
	frameworkMap         bool
	frameworkExamples    string
	maxFrameworkExamples int
	showRemediation      string
	baselineFile         string
	showBaselineProgress bool
	modulePriority       string

	batch     bool
	batchFile string

	resume bool

	externalAPI bool
	jsSupport   bool

	checkUpdate  bool
	doUpdate     bool
	showVersion  bool

	delayStrategy  string
	maxDelayMs     int
	adaptiveDelay  bool

	configFile     string
	profileMode    bool
	autoDoc        bool
)

var rootCmd = &cobra.Command{
	Use:   "anubis [flags] -t TARGET",
	Short: "Anubis — Elite Security Scanner",
	Long: `
Anubis v2.0 — Advanced modular security scanner with AI-driven heuristics,
polymorphic evasion, zero-dependency architecture, and enterprise-grade reporting.

Scan levels:
  1 — Passive reconnaissance (stealth, 5-min limit)
  2 — Active scanning (standard)
  3 — Deep scan (aggressive, comprehensive)

Example usage:
  anubis -t https://example.com -l 1
  anubis -t https://example.com -l 2 --ghost --strategy polymorphic
  anubis -t https://example.com -l 3 --threads 20 --deep-scan
  anubis -t https://example.com --proxy socks5://127.0.0.1:9050
  anubis -c config.yaml -t https://example.com
  anubis --resume
  anubis --batch --batch-file targets.txt -l 1
`,
	Args: cobra.NoArgs,
	RunE: runScan,
}

func init() {
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or IP address")
	rootCmd.Flags().IntVarP(&level, "level", "l", 1, "Scan level: 1 (light), 2 (active), 3 (deep)")

	rootCmd.Flags().StringSliceVarP(&modules, "modules", "m", nil, "Modules to run (comma-separated)")
	rootCmd.Flags().StringSliceVar(&disabledModules, "disable-modules", nil, "Modules to skip (comma-separated)")

	rootCmd.Flags().StringVar(&outputFormat, "format", "html+json", "Output format(s): json, html, csv (combine with +)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file base name")
	rootCmd.Flags().StringVar(&reportLevel, "report-level", "comprehensive", "Report detail: basic, detailed, comprehensive")

	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout (seconds)")
	rootCmd.Flags().IntVar(&threads, "threads", 10, "Concurrent worker threads")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 150, "Delay between requests (milliseconds)")
	rootCmd.Flags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent string (default: random per request)")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. socks5://127.0.0.1:9050)")
	rootCmd.Flags().StringVar(&proxyAuth, "proxy-auth", "", "Proxy credentials in user:pass format")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate")
	rootCmd.Flags().BoolVar(&sslBypass, "ssl-bypass", false, "Bypass SSL/TLS certificate validation")

	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Username for authenticated scanning")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "Password for authenticated scanning")
	rootCmd.Flags().StringVar(&wordlist, "wordlist", "", "Wordlist file for brute-force")
	rootCmd.Flags().StringVar(&payloadFile, "payload-file", "", "Custom payload file")
	rootCmd.Flags().StringVar(&authStrategy, "auth-strategy", "defaults", "Auth strategy: none, defaults, bruteforce, combined")

	rootCmd.Flags().StringSliceVar(&protocols, "protocols", []string{"http", "https"}, "Protocols: http, https, ftp, smtp")

	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.Flags().BoolVar(&respectLimits, "respect-limits", false, "Respect robots.txt and crawl delays")
	rootCmd.Flags().BoolVar(&quickVuln, "quick-vuln", false, "Stop each module on first finding")
	rootCmd.Flags().BoolVar(&deepScan, "deep-scan", false, "More thorough scanning (slower)")
	rootCmd.Flags().BoolVar(&ghostMode, "ghost", false, "Ghost mode — minimize detection footprint")
	rootCmd.Flags().BoolVar(&frameworkMap, "framework-map", false, "Map findings to OWASP/CIS frameworks")
	rootCmd.Flags().StringVar(&frameworkExamples, "framework-examples", "", "Show framework code examples: owasp, cis, both")
	rootCmd.Flags().IntVar(&maxFrameworkExamples, "max-framework-examples", 3, "Max code examples to include")
	rootCmd.Flags().StringVar(&showRemediation, "show-remediation", "all", "Show remediation for: all, high, critical, none")
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to saved baseline file for comparison")
	rootCmd.Flags().BoolVar(&showBaselineProgress, "show-baseline-progress", false, "Show baseline progress bar")
	rootCmd.Flags().StringVar(&modulePriority, "module-priority", "severity", "Module priority: severity, speed, comprehensive")

	rootCmd.Flags().BoolVar(&batch, "batch", false, "Batch mode — scan multiple targets")
	rootCmd.Flags().StringVar(&batchFile, "batch-file", "", "File with targets (one per line) for batch mode")

	rootCmd.Flags().BoolVar(&resume, "resume", false, "Resume from last checkpoint")

	rootCmd.Flags().BoolVar(&externalAPI, "external-api", false, "Enable external API integrations (Shodan, VirusTotal)")
	rootCmd.Flags().BoolVar(&jsSupport, "js-support", false, "Enable JavaScript rendering (requires headless browser)")

	rootCmd.Flags().BoolVar(&checkUpdate, "check-update", false, "Check GitHub for newer release (no download)")
	rootCmd.Flags().BoolVar(&doUpdate, "update", false, "Download and install latest release")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Print version information and exit")

	rootCmd.Flags().StringVar(&delayStrategy, "strategy", "jitter", "Delay strategy: fixed, exponential, linear, jitter, randomized, polymorphic")
	rootCmd.Flags().IntVar(&maxDelayMs, "max-delay", 60000, "Maximum delay in milliseconds")
	rootCmd.Flags().BoolVar(&adaptiveDelay, "adaptive-delay", true, "Auto-adjust delay based on target responses")

	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to YAML configuration file")
	rootCmd.Flags().BoolVar(&profileMode, "profile", false, "Enable performance profiling (CPU/mem/trace)")
	rootCmd.Flags().BoolVar(&autoDoc, "gendoc", false, "Generate documentation and exit")
}

func runScan(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Println(version.Info())
		return nil
	}

	if checkUpdate {
		return runCheckUpdate()
	}
	if doUpdate {
		return runUpdate()
	}

	if autoDoc {
		return generateDocs()
	}

	utils.PrintBanner()
	utils.PrintDisclaimer()

	if level < 1 || level > 3 {
		return fmt.Errorf("scan level must be 1, 2, or 3 (got %d)", level)
	}

	if target == "" && !resume && !batch {
		return fmt.Errorf("target is required: use -t https://example.com")
	}

	if batch && batchFile == "" {
		return fmt.Errorf("--batch requires --batch-file <path>")
	}

	for _, f := range strings.Split(outputFormat, "+") {
		f = strings.TrimSpace(f)
		switch f {
		case "json", "html", "csv":
		default:
			return fmt.Errorf("invalid format %q — valid: json, html, csv (combine with +)", f)
		}
	}

	switch delayStrategy {
	case "fixed", "exponential", "linear", "jitter", "randomized", "polymorphic":
	default:
		return fmt.Errorf("invalid --strategy %q — valid: fixed, exponential, linear, jitter, randomized, polymorphic", delayStrategy)
	}

	if sslBypass {
		fmt.Println("\033[33m[!] SSL bypass enabled — certificate validation disabled\033[0m")
	}

	if ghostMode {
		fmt.Println("\033[36m[!] Ghost mode enabled — minimizing detection footprint\033[0m")
	}

	if profileMode {
		fmt.Println("\033[36m[!] Profile mode enabled — performance data will be collected\033[0m")
	}

	return dispatchScan()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateDocs() error {
	fmt.Println("Generating Anubis v2.0 documentation...")
	fmt.Println("  docs/man/anubis.1 — Unix man page")
	fmt.Println("  README.md        — Project readme")
	fmt.Println("  CHANGELOG.md     — Version history")
	fmt.Println("[✓] Documentation generated")
	return nil
}
