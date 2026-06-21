package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/baseline"
	bruteforce "github.com/SepJs/anubis/pkg/modules/brute_force"
	"github.com/SepJs/anubis/pkg/modules/dns"
	"github.com/SepJs/anubis/pkg/modules/fingerprint"
	"github.com/SepJs/anubis/pkg/modules/headers"
	"github.com/SepJs/anubis/pkg/modules/portscan"
	"github.com/SepJs/anubis/pkg/modules/sensitive"
	sslmod "github.com/SepJs/anubis/pkg/modules/ssl"
	"github.com/SepJs/anubis/pkg/modules/sqli"
	"github.com/SepJs/anubis/pkg/modules/xss"
	"github.com/SepJs/anubis/pkg/report"
	"github.com/SepJs/anubis/pkg/scanner"
	"github.com/SepJs/anubis/pkg/state"
	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
)

// reportsDir is the directory where all scan reports are saved.
// Created automatically if it doesn't exist.
const reportsDir = "reports"

// allModules returns all registered scan modules, ordered roughly by
// execution speed (fast passive checks first, slower active checks last).
func allModules() []scanner.Module {
	return []scanner.Module{
		portscan.New(),    // Level 1 — TCP port scan
		sslmod.New(),      // Level 1 — TLS/SSL analysis
		headers.New(),     // Level 1 — HTTP security headers
		sensitive.New(),   // Level 1 — exposed sensitive files
		dns.New(),         // Level 2 — DNS enumeration
		sqli.New(),        // Level 2 — SQL injection
		xss.New(),         // Level 2 — reflected XSS
		bruteforce.New(),  // Level 2 — default credentials
		fingerprint.New(), // Level 3 — stack fingerprinting
	}
}

// dispatchScan routes to the correct scan mode based on flags.
func dispatchScan() error {
	// Run background update check on every scan start.
	// Non-blocking — fires in a goroutine and prints a notice if an update
	// is found, but never delays or blocks the actual scan.
	go backgroundUpdateCheck()

	cfg := buildConfig()

	if resume {
		return resumeScan(cfg)
	}
	if batch {
		return batchScan(cfg)
	}
	return runSingleScan(cfg)
}

// backgroundUpdateCheck silently checks GitHub for a newer release.
// If one exists, it prints a one-line notice after a short delay so it
// appears after the scan pre-info block rather than interrupting it.
func backgroundUpdateCheck() {
	time.Sleep(500 * time.Millisecond) // let pre-scan output settle first

	release, err := version.FetchLatest()
	if err != nil {
		// Silently ignore — offline, no releases yet, or rate-limited.
		return
	}
	if version.IsNewer(release.TagName) {
		fmt.Printf("\n  [!] Update available: %s → %s\n", version.Version, release.TagName)
		fmt.Printf("      Run 'anubis --update' or visit %s\n\n", release.HTMLURL)
	}
}

// buildConfig maps CLI flag variables onto a ScanConfig struct.
func buildConfig() scanner.ScanConfig {
	return scanner.ScanConfig{
		Target:               utils.NormalizeTarget(target),
		Level:                scanner.ScanLevel(level),
		Modules:              modules,
		DisabledModules:      disabledModules,
		OutputFormat:         outputFormat,
		OutputFile:           outputFile,
		ReportLevel:          reportLevel,
		Timeout:              timeout,
		Threads:              threads,
		RateLimit:            rateLimit,
		DelayStrategy:        delayStrategy,
		MaxDelayMs:           maxDelayMs,
		AdaptiveDelay:        adaptiveDelay,
		UserAgent:            userAgent,
		ProxyURL:             proxyURL,
		ProxyAuth:            proxyAuth,
		CACert:               caCert,
		SSLBypass:            sslBypass,
		Username:             username,
		Password:             password,
		Wordlist:             wordlist,
		PayloadFile:          payloadFile,
		AuthStrategy:         authStrategy,
		Protocols:            protocols,
		Verbose:              verbose,
		RespectLimits:        respectLimits,
		QuickVuln:            quickVuln,
		DeepScan:             deepScan,
		FrameworkMap:         frameworkMap,
		FrameworkExamples:    frameworkExamples,
		MaxFrameworkExamples: maxFrameworkExamples,
		ShowRemediation:      showRemediation,
		BaselineFile:         baselineFile,
		ShowBaselineProgress: showBaselineProgress,
		ModulePriority:       modulePriority,
		Batch:                batch,
		BatchFile:            batchFile,
		Resume:               resume,
		ExternalAPI:          externalAPI,
		JSSupport:            jsSupport,
	}
}

// ensureReportsDir creates the reports output directory if it doesn't exist.
func ensureReportsDir() error {
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return fmt.Errorf("cannot create reports directory %q: %w", reportsDir, err)
	}
	return nil
}

// resolveOutputFile returns the full path for the report file.
// If the user didn't specify --output, it auto-generates a timestamped name
// inside the reports/ directory.
func resolveOutputFile(cfg scanner.ScanConfig) string {
	if cfg.OutputFile != "" {
		// User specified a name — if it has no directory component, put it
		// inside reports/ automatically.
		if filepath.Dir(cfg.OutputFile) == "." {
			return filepath.Join(reportsDir, cfg.OutputFile)
		}
		return cfg.OutputFile
	}
	// Auto-generate: reports/anubis_<host>_<timestamp>
	host := sanitizeFilename(cfg.Target)
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(reportsDir, fmt.Sprintf("anubis_%s_%s", host, ts))
}

// runSingleScan executes a complete scan for one target and saves reports.
func runSingleScan(cfg scanner.ScanConfig) error {
	// Ensure reports directory exists before the scan starts.
	if err := ensureReportsDir(); err != nil {
		utils.LogWarn("%v", err)
	}

	// Resolve the final output file path.
	cfg.OutputFile = resolveOutputFile(cfg)

	// Level 0 baseline — measure normal response times before active scanning.
	baselineMetrics, err := collectBaseline(cfg)
	if err != nil {
		utils.LogWarn("Baseline collection failed: %v — continuing without baseline", err)
	}

	// Compare against a previously saved baseline if one was provided.
	if cfg.BaselineFile != "" && baselineMetrics != nil {
		previous, err := baseline.LoadFromFile(cfg.BaselineFile)
		if err != nil {
			utils.LogWarn("Could not load baseline file: %v", err)
		} else {
			baseline.Compare(previous, baselineMetrics)
		}
	}

	// Save current baseline inside reports/ for future comparison.
	if baselineMetrics != nil {
		bPath := filepath.Join(reportsDir, "anubis_baseline.json")
		if err := baseline.SaveToFile(baselineMetrics, bPath); err != nil {
			utils.LogDebug(cfg.Verbose, "Could not save baseline: %v", err)
		}
	}

	printPreScanInfo(cfg)

	engine := scanner.NewEngine(cfg, allModules())
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if baselineMetrics != nil {
		result.BaselineData = baselineMetrics
	}

	report.PrintTerminalSummary(result)

	if err := report.Generate(result, cfg.OutputFormat, cfg.OutputFile, cfg.ReportLevel); err != nil {
		utils.LogWarn("Report generation error: %v", err)
	} else {
		utils.LogSuccess("Reports saved to: %s/", reportsDir)
	}

	if state.Exists() {
		state.Delete()
	}

	return nil
}

// resumeScan loads a checkpoint and continues scanning remaining modules.
func resumeScan(cfg scanner.ScanConfig) error {
	if !state.Exists() {
		return fmt.Errorf("no checkpoint file found at %s — cannot resume", state.StateFile)
	}

	checkpoint, err := state.Load()
	if err != nil {
		return fmt.Errorf("resume: load checkpoint: %w", err)
	}

	utils.LogInfo("Resuming scan for target: %s", checkpoint.Target)
	utils.LogInfo("Completed modules:  %s", strings.Join(checkpoint.CompletedModules, ", "))
	utils.LogInfo("Remaining modules:  %s", strings.Join(checkpoint.RemainingModules, ", "))

	resumeCfg := checkpoint.Flags
	resumeCfg.Target = checkpoint.Target
	resumeCfg.Level = checkpoint.Level
	resumeCfg.Modules = checkpoint.RemainingModules
	resumeCfg.OutputFile = resolveOutputFile(resumeCfg)

	if err := ensureReportsDir(); err != nil {
		utils.LogWarn("%v", err)
	}

	engine := scanner.NewEngine(resumeCfg, allModules())
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("resume scan failed: %w", err)
	}

	// Merge findings from the previous partial scan
	result.AllFindings = append(checkpoint.Findings, result.AllFindings...)

	report.PrintTerminalSummary(result)

	if err := report.Generate(result, resumeCfg.OutputFormat, resumeCfg.OutputFile, resumeCfg.ReportLevel); err != nil {
		utils.LogWarn("Report generation error: %v", err)
	}

	state.Delete()
	return nil
}

// batchScan reads a list of targets from a file and scans each one.
func batchScan(cfg scanner.ScanConfig) error {
	if cfg.BatchFile == "" {
		return fmt.Errorf("--batch requires --batch-file <path>")
	}

	targets, err := readTargetFile(cfg.BatchFile)
	if err != nil {
		return fmt.Errorf("batch: read targets: %w", err)
	}

	utils.LogInfo("Batch mode: %d targets from %s", len(targets), cfg.BatchFile)

	for i, t := range targets {
		utils.PrintSeparator()
		utils.LogInfo("Batch [%d/%d]: %s", i+1, len(targets), t)

		batchCfg := cfg
		batchCfg.Target = utils.NormalizeTarget(t)
		// output file is resolved per-target inside runSingleScan
		batchCfg.OutputFile = ""

		if err := runSingleScan(batchCfg); err != nil {
			utils.LogWarn("Scan failed for %s: %v", t, err)
		}
	}

	utils.LogSuccess("Batch complete: %d targets processed", len(targets))
	return nil
}

// collectBaseline runs the Level 0 baseline measurement.
func collectBaseline(cfg scanner.ScanConfig) (*baseline.Metrics, error) {
	return baseline.Collect(cfg.Target, cfg.ShowBaselineProgress)
}

// printPreScanInfo prints a summary of scan configuration before starting.
func printPreScanInfo(cfg scanner.ScanConfig) {
	utils.PrintSeparator()
	utils.LogInfo("Target:    %s", cfg.Target)
	utils.LogInfo("Level:     %d", cfg.Level)
	utils.LogInfo("Threads:   %d", cfg.Threads)
	utils.LogInfo("Timeout:   %ds", cfg.Timeout)
	utils.LogInfo("Rate:      %dms (%s strategy)", cfg.RateLimit, cfg.DelayStrategy)
	utils.LogInfo("Reports:   %s/", reportsDir)
	if cfg.ProxyURL != "" {
		utils.LogInfo("Proxy:     %s", cfg.ProxyURL)
	}
	if cfg.SSLBypass {
		utils.LogWarn("SSL bypass enabled")
	}
	if cfg.AdaptiveDelay {
		utils.LogInfo("Adaptive delay: enabled")
	}
	utils.PrintSeparator()
}

// readTargetFile reads a newline-separated list of targets, skipping blank
// lines and lines starting with #.
func readTargetFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, nil
}

// sanitizeFilename replaces characters that aren't safe in file names.
func sanitizeFilename(s string) string {
	r := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
		".", "_",
	)
	result := r.Replace(s)
	if len(result) > 40 {
		result = result[:40]
	}
	return result
}
