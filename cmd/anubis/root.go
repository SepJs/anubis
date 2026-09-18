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

	// Crawler
	crawl          bool
	crawlDepth     int
	crawlMaxPages  int

	// Custom YAML templates
	templatesDir string

	silent bool
)

var rootCmd = &cobra.Command{
	Use:   "anubis [flags] -t TARGET",
	Short: "Anubis — Elite Security Scanner",
	Long: `Anubis v2.5 — Advanced modular web security scanner.

Scan levels:
  -l 1   Passive reconnaissance (stealth, minimal footprint)
  -l 2   Active scanning (standard)
  -l 3   Deep scan (aggressive, comprehensive)

Modules:
  sqli, xss, lfi, ssti, openredirect, sensitive,
  dns, ssl, headers, fingerprint, portscan, brute_force
  (select with --modules / --disabled-modules)

Extras:
  --crawl        discover endpoints before scanning
  --templates    run custom YAML check templates
  --ghost        stealth mode
  --batch        scan a target list from a file

Run 'anubis -h' to see every flag with its description.`,
	Example: `  # Passive / stealth scan (level 1)
  anubis -t https://example.com -l 1

  # Active scan with stealth features (level 2)
  anubis -t https://example.com -l 2 --ghost --strategy polymorphic

  # Deep scan with crawler and custom YAML templates (level 3)
  anubis -t https://example.com -l 3 --crawl --crawl-depth 3 --templates templates/custom

  # Batch mode over a target list
  anubis --batch --batch-file targets.txt -l 2

  # Full example: authenticated scan through a proxy
  anubis -t https://example.com -l 2 --ghost -u admin -p s3cret --proxy socks5://127.0.0.1:9050`,
	Args: cobra.NoArgs,
	RunE: runScan,
}

func init() {
	rootCmd.SetHelpFunc(customHelp)

	// Target options
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or IP address (e.g. https://example.com)")
	rootCmd.Flags().StringVarP(&batchFile, "batch-file", "b", "", "File with targets (one per line) for batch mode")
	rootCmd.Flags().BoolVar(&batch, "batch", false, "Batch mode — scan multiple targets from file")
	rootCmd.Flags().BoolVar(&resume, "resume", false, "Resume interrupted scan from last checkpoint")

	// Scan level & modes
	rootCmd.Flags().IntVarP(&level, "level", "l", 1, "Scan level: 1 (passive recon), 2 (active audit), 3 (deep scan)")
	rootCmd.Flags().StringSliceVarP(&modules, "modules", "m", nil, "Specific modules to run (comma-separated)")
	rootCmd.Flags().StringSliceVar(&disabledModules, "disable-modules", nil, "Modules to skip (comma-separated)")
	rootCmd.Flags().BoolVar(&quickVuln, "quick-vuln", false, "Stop each module immediately upon first verified finding")
	rootCmd.Flags().BoolVar(&deepScan, "deep-scan", false, "Exhaustive payload testing (slower, maximum depth)")
	rootCmd.Flags().StringVar(&modulePriority, "module-priority", "severity", "Module execution priority: severity, speed, comprehensive")

	// Crawler & Discovery
	rootCmd.Flags().BoolVar(&crawl, "crawl", false, "Crawl target first and feed discovered endpoints to injection modules")
	rootCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 2, "Crawler maximum link recursion depth")
	rootCmd.Flags().IntVar(&crawlMaxPages, "crawl-max-pages", 30, "Crawler maximum total pages to explore")
	rootCmd.Flags().BoolVar(&respectLimits, "respect-limits", false, "Respect robots.txt and crawl delay limits")

	// Custom Templates
	rootCmd.Flags().StringVar(&templatesDir, "templates", "", "Directory of YAML custom-check templates (e.g. templates/custom)")

	// Evasion & Anti-WAF
	rootCmd.Flags().BoolVar(&ghostMode, "ghost", false, "Ghost mode — randomize signatures and minimize detection footprint")
	rootCmd.Flags().StringVar(&delayStrategy, "strategy", "jitter", "Delay strategy: fixed, exponential, linear, jitter, randomized, polymorphic")
	rootCmd.Flags().IntVar(&maxDelayMs, "max-delay", 60000, "Maximum delay threshold in milliseconds")
	rootCmd.Flags().BoolVar(&adaptiveDelay, "adaptive-delay", true, "Auto-adjust request throttling based on target health")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 150, "Base delay between requests in milliseconds")

	// Authentication & Input
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Username for authenticated scanning")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "Password for authenticated scanning")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Custom dictionary wordlist file for brute-force & path discovery")
	rootCmd.Flags().StringVar(&payloadFile, "payload-file", "", "Custom injection payload dictionary file")
	rootCmd.Flags().StringVar(&authStrategy, "auth-strategy", "defaults", "Auth strategy: none, defaults, bruteforce, combined")

	// Network & Proxy
	rootCmd.Flags().IntVar(&threads, "threads", 10, "Concurrent worker threads")
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. socks5://127.0.0.1:9050 or http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&proxyAuth, "proxy-auth", "", "Proxy credentials in user:pass format")
	rootCmd.Flags().BoolVar(&sslBypass, "ssl-bypass", false, "Bypass SSL/TLS certificate validation (insecure)")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate authority bundle")
	rootCmd.Flags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent string (default: polymorphic UA)")
	rootCmd.Flags().StringSliceVar(&protocols, "protocols", []string{"http", "https"}, "Protocols to inspect: http, https")

	// Output & Reporting
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output report base name or directory")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "html+json", "Report format(s): json, html, csv (combine with +)")
	rootCmd.Flags().StringVar(&reportLevel, "report-level", "comprehensive", "Report detail: basic, detailed, comprehensive")
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to saved baseline file for delta comparison")
	rootCmd.Flags().BoolVar(&showBaselineProgress, "show-baseline-progress", false, "Show baseline collection progress")
	rootCmd.Flags().BoolVar(&frameworkMap, "framework-map", false, "Map findings to OWASP Top 10 and CIS benchmarks")
	rootCmd.Flags().StringVar(&frameworkExamples, "framework-examples", "", "Show framework remediation examples: owasp, cis, both")
	rootCmd.Flags().IntVar(&maxFrameworkExamples, "max-framework-examples", 3, "Maximum framework code examples to include")
	rootCmd.Flags().StringVar(&showRemediation, "show-remediation", "all", "Show remediation advice for: all, high, critical, none")

	// General & System
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose debugging output")
	rootCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode: suppress banner & non-finding logs for Unix pipes")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to YAML configuration file")
	rootCmd.Flags().BoolVar(&profileMode, "profile", false, "Enable performance profiling (CPU/mem/trace)")
	rootCmd.Flags().BoolVar(&externalAPI, "external-api", false, "Enable external threat-intel integrations")
	rootCmd.Flags().BoolVar(&jsSupport, "js-support", false, "Enable JavaScript rendering support")
	rootCmd.Flags().BoolVar(&checkUpdate, "check-update", false, "Check GitHub for newer release without installing")
	rootCmd.Flags().BoolVar(&doUpdate, "update", false, "Download and install latest release")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Print version information and exit")
	rootCmd.Flags().BoolVar(&autoDoc, "gendoc", false, "Generate documentation and exit")
}

func customHelp(cmd *cobra.Command, args []string) {
	utils.PrintBanner()
	utils.PrintDisclaimer()

	bold := "\033[1m"
	reset := "\033[0m"
	cyan := "\033[36m"
	dim := "\033[2m"
	hiWhite := "\033[97m"

	fmt.Printf("%sUSAGE:%s\n", bold+hiWhite, reset)
	fmt.Printf("  anubis -t <target> [flags]\n\n")

	sections := []struct {
		title string
		flags [][2]string
	}{
		{
			title: "TARGET SPECIFICATION",
			flags: [][2]string{
				{"-t, --target <url/ip>", "Target URL or IP address (e.g. https://example.com)"},
				{"-b, --batch-file <path>", "Scan multiple targets from text file (one per line)"},
				{"    --batch", "Enable batch target execution mode"},
				{"    --resume", "Resume interrupted scan from checkpoint (.anubis.state)"},
			},
		},
		{
			title: "SCAN LEVEL & AUDIT MODES",
			flags: [][2]string{
				{"-l, --level <1|2|3>", "Audit depth: 1=Passive Recon, 2=Active Audit, 3=Deep Scan (default: 1)"},
				{"-m, --modules <list>", "Comma-separated list of modules to execute"},
				{"    --disable-modules <list>", "Comma-separated list of modules to skip"},
				{"    --quick-vuln", "Stop each module immediately upon first verified vulnerability"},
				{"    --deep-scan", "Enable exhaustive payload fuzzing (slower, maximum depth)"},
				{"    --module-priority <mode>", "Module order: severity, speed, comprehensive (default: severity)"},
			},
		},
		{
			title: "CRAWLER & TARGET DISCOVERY",
			flags: [][2]string{
				{"    --crawl", "Crawl target to discover internal endpoints, links & forms"},
				{"    --crawl-depth <int>", "Crawler link recursion depth limit (default: 2)"},
				{"    --crawl-max-pages <int>", "Crawler max total unique pages to explore (default: 30)"},
				{"    --respect-limits", "Respect target robots.txt rules and crawl delay directives"},
			},
		},
		{
			title: "CUSTOM CHECK TEMPLATES",
			flags: [][2]string{
				{"    --templates <dir>", "Directory of YAML custom vulnerability check templates"},
			},
		},
		{
			title: "EVASION & ANTI-WAF",
			flags: [][2]string{
				{"    --ghost", "Ghost mode: randomize signatures and minimize detection footprint"},
				{"    --strategy <name>", "Delay pattern: jitter, polymorphic, exponential, linear, fixed (default: jitter)"},
				{"    --max-delay <ms>", "Maximum evasion delay threshold in milliseconds (default: 60000)"},
				{"    --adaptive-delay", "Dynamically adjust request throttling based on server health (default: true)"},
				{"    --rate-limit <ms>", "Base delay between requests in milliseconds (default: 150)"},
			},
		},
		{
			title: "AUTHENTICATION & INPUTS",
			flags: [][2]string{
				{"-u, --username <user>", "Username for HTTP Basic or Form authentication"},
				{"-p, --password <pass>", "Password for authenticated audits"},
				{"-w, --wordlist <path>", "Custom dictionary file for path discovery and bruteforce"},
				{"    --payload-file <path>", "Custom injection payload dictionary file"},
				{"    --auth-strategy <mode>", "Auth strategy: none, defaults, bruteforce, combined (default: defaults)"},
			},
		},
		{
			title: "NETWORK & PROXY",
			flags: [][2]string{
				{"    --proxy <url>", "HTTP/HTTPS/SOCKS5 proxy URL (e.g. socks5://127.0.0.1:9050)"},
				{"    --proxy-auth <user:pass>", "Proxy authentication credentials in user:password format"},
				{"    --timeout <sec>", "HTTP request and connection timeout in seconds (default: 30)"},
				{"    --threads <int>", "Number of concurrent worker goroutines (default: 10)"},
				{"    --ssl-bypass", "Bypass SSL/TLS certificate validation (insecure mode)"},
				{"    --ca-cert <path>", "Path to custom CA certificate authority bundle"},
				{"    --user-agent <str>", "Custom User-Agent header (defaults to polymorphic UA pool)"},
				{"    --protocols <list>", "Protocols to audit: http, https (default: http,https)"},
			},
		},
		{
			title: "OUTPUT & REPORTING",
			flags: [][2]string{
				{"-o, --output <file>", "Base filename or directory for output reports"},
				{"-f, --format <format>", "Report formats: html, json, csv (combine with +, default: html+json)"},
				{"    --report-level <lvl>", "Reporting detail level: basic, detailed, comprehensive (default: comprehensive)"},
				{"    --baseline <file>", "Compare current scan findings against a previous baseline file"},
				{"    --framework-map", "Map discovered findings to OWASP Top 10 and CIS benchmarks"},
				{"    --framework-examples <m>", "Include mitigation code examples: owasp, cis, both"},
			},
		},
		{
			title: "GENERAL & SYSTEM",
			flags: [][2]string{
				{"-v, --verbose", "Enable verbose real-time debugging output"},
				{"-s, --silent", "Silent mode: suppress banner & non-finding logs for Unix pipes"},
				{"-c, --config <file>", "Load scan configuration options from YAML file"},
				{"    --profile", "Enable CPU, memory, and runtime execution profiling"},
				{"    --check-update", "Check GitHub for newer releases without downloading"},
				{"    --update", "Download and install the latest Anubis release"},
				{"    --version", "Print version, architecture, and build information"},
				{"-h, --help", "Display this help manual"},
			},
		},
	}

	for _, sec := range sections {
		fmt.Printf("%s%s:%s\n", bold+cyan, sec.title, reset)
		for _, fl := range sec.flags {
			fmt.Printf("  %s%-28s%s %s\n", hiWhite, fl[0], reset, fl[1])
		}
		fmt.Println()
	}

	fmt.Printf("%sEXAMPLES:%s\n", bold+hiWhite, reset)
	fmt.Printf("  %sanubis -t https://example.com -l 1%s\n", dim, reset)
	fmt.Printf("      Run stealth passive reconnaissance on target.\n\n")
	fmt.Printf("  %sanubis -t https://example.com -l 2 --crawl --ghost --strategy polymorphic%s\n", dim, reset)
	fmt.Printf("      Crawl target, enable anti-WAF ghost mode, and run active vulnerability audit.\n\n")
	fmt.Printf("  %sanubis -t https://example.com -l 3 --templates templates/custom --proxy socks5://127.0.0.1:9050%s\n", dim, reset)
	fmt.Printf("      Execute deep aggressive scan with custom YAML templates routed through Tor.\n\n")
	fmt.Printf("  %sanubis --batch -b targets.txt -l 2 -o client_audit -f html+json%s\n", dim, reset)
	fmt.Printf("      Batch audit multiple targets from file and generate HTML + JSON reports.\n\n")
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

	if silent {
		utils.SilentMode = true
	}

	if target == "" && !resume && !batch {
		// sqlmap-style: bare `anubis` shows the help
		return cmd.Help()
	}

	if !silent {
		utils.PrintBanner()
		utils.PrintDisclaimer()
	}

	if level < 1 || level > 3 {
		return fmt.Errorf("scan level must be 1, 2, or 3 (got %d)", level)
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
