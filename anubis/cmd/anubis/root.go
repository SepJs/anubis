package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/innervoid/anubis/pkg/utils"
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
)

var rootCmd = &cobra.Command{
	Use:   "anubis [options]",
	Short: "Anubis — Modular Web Security Scanner",
	Long:  `Anubis is an advanced modular security scanner built for authorized penetration testing.`,
	Args:  cobra.NoArgs,
	RunE:  runScan,
}

func init() {
	// ۱. تعریف تمام پرچم‌ها بدون هیچ حذفیاتی
	// Target Option
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or IP address (e.g. https://target.com)")
	rootCmd.Flags().IntVarP(&level, "level", "l", 1, "Scan level: 1 (passive), 2 (active), 3 (deep)")

	// Module control
	rootCmd.Flags().StringSliceVarP(&modules, "modules", "m", nil, "Specific modules to run (comma-separated)")
	rootCmd.Flags().StringSliceVar(&disabledModules, "disable-modules", nil, "Modules to exclude from execution")

	// Output
	rootCmd.Flags().StringVar(&outputFormat, "format", "html+json", "Formats: json, html, csv (combine with +)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file base name")
	rootCmd.Flags().StringVar(&reportLevel, "report-level", "comprehensive", "Detail level: basic, detailed, comprehensive")

	// Connection
	rootCmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	rootCmd.Flags().IntVar(&threads, "threads", 5, "Number of concurrent worker threads")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 150, "Delay between requests in milliseconds")
	rootCmd.Flags().StringVar(&userAgent, "user-agent", "Mozilla/5.0 (compatible; Anubis-Scanner/1.0)", "Custom User-Agent header")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&proxyAuth, "proxy-auth", "", "Proxy credentials (user:pass)")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "Path to custom CA certificate file")
	rootCmd.Flags().BoolVar(&sslBypass, "ssl-bypass", false, "Bypass SSL/TLS validation checks")

	// Auth
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Username for authenticated sessions")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "Password for authenticated sessions")
	rootCmd.Flags().StringVar(&wordlist, "wordlist", "", "Wordlist path for brute-force attacks")
	rootCmd.Flags().StringVar(&payloadFile, "payload-file", "", "Custom vulnerability injection payloads")
	rootCmd.Flags().StringVar(&authStrategy, "auth-strategy", "defaults", "Strategy: none, defaults, bruteforce, combined")

	// Optimization & Behavior
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed debug and transit logs")
	rootCmd.Flags().BoolVar(&respectLimits, "respect-limits", false, "Adhere to robots.txt and crawl delays")
	rootCmd.Flags().BoolVar(&quickVuln, "quick-vuln", false, "Exit module immediately on first vulnerability found")
	rootCmd.Flags().BoolVar(&deepScan, "deep-scan", false, "Enable absolute comprehensive analysis (slower)")
	rootCmd.Flags().BoolVar(&frameworkMap, "framework-map", false, "Map results to OWASP / CIS frameworks")
	rootCmd.Flags().StringVar(&frameworkExamples, "framework-examples", "", "Show code fixes: owasp, cis, both")
	rootCmd.Flags().IntVar(&maxFrameworkExamples, "max-framework-examples", 3, "Maximum remediation examples displayed")
	rootCmd.Flags().StringVar(&showRemediation, "show-remediation", "all", "Show remedies for: all, high, critical, none")
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to prior baseline file for diff comparisons")
	rootCmd.Flags().BoolVar(&showBaselineProgress, "show-baseline-progress", true, "Render active baseline tracking bar")
	rootCmd.Flags().StringVar(&modulePriority, "module-priority", "severity", "Priority order: severity, speed")

	// Automation / Advanced
	rootCmd.Flags().BoolVar(&batch, "batch", false, "Automated batch scanning against multiple hosts")
	rootCmd.Flags().StringVar(&batchFile, "batch-file", "", "File descriptor containing line-separated targets")
	rootCmd.Flags().BoolVar(&resume, "resume", false, "Restore operation from last state checkpoint")
	rootCmd.Flags().BoolVar(&externalAPI, "external-api", false, "Integrate passive intelligence APIs (Shodan, VT)")
	rootCmd.Flags().BoolVar(&jsSupport, "js-support", false, "Execute headless engine for full JS rendering")
	rootCmd.Flags().StringSliceVar(&protocols, "protocols", []string{"http", "https"}, "Target protocols layer")

	// ۲. تنظیم کاستوم هلپ
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printFullUsageExtended(cmd)
	})
}

// ۳. منوی مینیمال اولیه با امضای اختصاصی خودت
func printMinimalBannerStart() {
	utils.PrintBanner()
	
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()

	fmt.Printf("%s %s\n\n", cyan("[*] Powered By:"), white("Unknown Xrg"))

	fmt.Printf("%s\n", red("[-] LEGAL DISCLAIMER & USAGE WARNING:"))
	fmt.Printf("  %s\n", white("This tool is strictly designed for authorized cybersecurity assessments and penetration testing."))
	fmt.Printf("  %s\n\n", red("Any legal consequences, damages, or misuse of this software are entirely the responsibility of the user."))

	fmt.Printf("%s\n", yellow("To view all available scan switches and advanced configurations, run:"))
	fmt.Printf("  %s %s\n\n", green("anubis"), white("-h"))
}

// ۴. منوی کامل و تفکیک‌شده شبیه به SQLMap بدون اسم استودیو
func printFullUsageExtended(cmd *cobra.Command) {
	utils.PrintBanner()
	
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()

	fmt.Printf("%s %s\n\n", cyan("[*] Powered By:"), white("Unknown Xrg"))

	fmt.Printf("%s\n  anubis -t <target> [options]\n\n", yellow("Usage:"))

	// لیست کامل تمام آپشن‌ها دسته‌بندی‌شده
	fmt.Printf("%s\n", cyan("Target Options:"))
	fmt.Printf("  -t, --target                 %-15s %s\n", "TARGET", white("Target URL or IP address (e.g. https://example.com)"))
	fmt.Printf("  -l, --level                  %-15s %s\n", "LEVEL", white("Scan level: 1 (Passive), 2 (Active), 3 (Deep Scan) [Default: 1]"))

	fmt.Printf("\n%s\n", cyan("Module Optimization:"))
	fmt.Printf("  -m, --modules                %-15s %s\n", "MODULES", white("Comma-separated modules to run explicitly"))
	fmt.Printf("      --disable-modules        %-15s %s\n", "MODULES", white("List of modules to bypass during execution loop"))
	fmt.Printf("      --module-priority        %-15s %s\n", "PRIORITY", white("Priority order: severity, speed, comprehensive [Default: severity]"))

	fmt.Printf("\n%s\n", cyan("Request / Connection Adjustments:"))
	fmt.Printf("      --threads                %-15s %s\n", "NUM", white("Max concurrent engine processing threads [Default: 5]"))
	fmt.Printf("      --timeout                %-15s %s\n", "SEC", white("HTTP/TCP link expiration window [Default: 30s]"))
	fmt.Printf("      --rate-limit             %-15s %s\n", "MS", white("Forced wait time between request waves [Default: 150ms]"))
	fmt.Printf("      --user-agent             %-15s %s\n", "STR", white("Custom User-Agent string to spoof scanner identity"))
	fmt.Printf("      --proxy                  %-15s %s\n", "URL", white("Route traffic over proxy infrastructure (e.g. http://127.0.0.1:8080)"))
	fmt.Printf("      --proxy-auth             %-15s %s\n", "AUTH", white("Proxy credentials in user:pass format"))
	fmt.Printf("      --ca-cert                %-15s %s\n", "PATH", white("Path to custom CA certificate verification file"))
	fmt.Printf("      --ssl-bypass             %-15s %s\n", "", white("Ignore expired/untrusted upstream SSL/TLS certificates"))
	fmt.Printf("      --protocols              %-15s %s\n", "LIST", white("Target application protocols layer [Default: http,https]"))

	fmt.Printf("\n%s\n", cyan("Target Authentication & Payload Injection:"))
	fmt.Printf("  -u, --username               %-15s %s\n", "USER", white("Provide identifier for stateful app scanning"))
	fmt.Printf("  -p, --password               %-15s %s\n", "PASS", white("Provide credential secret for authenticated sessions"))
	fmt.Printf("      --wordlist               %-15s %s\n", "FILE", white("Custom wordlist injection path for brute-force vectors"))
	fmt.Printf("      --payload-file           %-15s %s\n", "FILE", white("Custom engineering payload file override"))
	fmt.Printf("      --auth-strategy          %-15s %s\n", "STRAT", white("Strategy: none, defaults, bruteforce, combined [Default: defaults]"))

	fmt.Printf("\n%s\n", cyan("Scan Optimization & Behavior:"))
	fmt.Printf("  -v, --verbose                %-15s %s\n", "", white("Print full payload activity stream and debug logs onto stdout"))
	fmt.Printf("      --respect-limits         %-15s %s\n", "", white("Adhere strictly to target robots.txt limits and crawl delays"))
	fmt.Printf("      --quick-vuln             %-15s %s\n", "", white("Exit active module immediately on first vulnerability discovery"))
	fmt.Printf("      --deep-scan              %-15s %s\n", "", white("Enable absolute comprehensive deep directory analysis (slower)"))
	fmt.Printf("      --framework-map          %-15s %s\n", "", white("Map structural findings to OWASP / CIS compliance frameworks"))
	fmt.Printf("      --framework-examples     %-15s %s\n", "TYPE", white("Show compliance code fixes: owasp, cis, both"))
	fmt.Printf("      --max-framework-examples %-15s %s\n", "NUM", white("Maximum remediation code examples displayed [Default: 3]"))
	fmt.Printf("      --show-remediation       %-15s %s\n", "LEVEL", white("Show remedies for: all, high, critical, none [Default: all]"))
	fmt.Printf("      --baseline               %-15s %s\n", "FILE", white("Path to prior baseline metrics file for diff comparison parsing"))
	fmt.Printf("      --show-baseline-progress %-15s %s\n", "BOOL", white("Render active baseline verification tracking bar [Default: true]"))

	fmt.Printf("\n%s\n", cyan("Reporting & Output Configuration:"))
	fmt.Printf("      --format                 %-15s %s\n", "FORMAT", white("Report schemas: json, html, csv (Merge with '+') [Default: html+json]"))
	fmt.Printf("  -o, --output                 %-15s %s\n", "NAME", white("Base output reports filename override mapping"))
	fmt.Printf("      --report-level           %-15s %s\n", "DETAIL", white("Report depth representation: basic, detailed, comprehensive"))

	fmt.Printf("\n%s\n", cyan("Automation & Advanced Extensions:"))
	fmt.Printf("      --batch                  %-15s %s\n", "", white("Run non-interactive scanner sweep for massive targets lists"))
	fmt.Printf("      --batch-file             %-15s %s\n", "FILE", white("Source text file containing line-separated target items"))
	fmt.Printf("      --resume                 %-15s %s\n", "", white("Hot-restore engine workflow from saved session state logs"))
	fmt.Printf("      --external-api           %-15s %s\n", "", white("Integrate passive external intelligence streams (Shodan, VT)"))
	fmt.Printf("      --js-support             %-15s %s\n", "", white("Execute integrated headless browser for full client JS rendering"))

	fmt.Printf("\n%s\n", cyan("Examples:"))
	fmt.Printf("  %s %s\n", green("anubis"), white("-t https://example.com -l 1"))
	fmt.Printf("  %s %s\n", green("anubis"), white("-t https://example.com -l 2 --format json -o target_report"))
	fmt.Printf("  %s %s\n", green("anubis"), white("--batch --batch-file targets.txt -l 2"))
	fmt.Printf("  %s %s\n\n", green("anubis"), blue("--resume"))
}

func runScan(cmd *cobra.Command, args []string) error {
	if target == "" && !resume && !batch {
		printMinimalBannerStart()
		os.Exit(0)
	}

	utils.PrintBanner()
	utils.PrintDisclaimer()

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

	if sslBypass {
		color.Yellow("[!] SSL bypass enabled — certificate validation disabled")
	}

	return dispatchScan()
}

func Execute() {
	if len(os.Args) == 1 {
		printMinimalBannerStart()
		os.Exit(0)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
