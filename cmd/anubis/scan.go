package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/innervoid/anubis/pkg/baseline"
	bruteforce "github.com/innervoid/anubis/pkg/modules/brute_force"
	"github.com/innervoid/anubis/pkg/modules/dns"
	"github.com/innervoid/anubis/pkg/modules/fingerprint"
	"github.com/innervoid/anubis/pkg/modules/headers"
	"github.com/innervoid/anubis/pkg/modules/portscan"
	"github.com/innervoid/anubis/pkg/modules/sensitive"
	sslmod "github.com/innervoid/anubis/pkg/modules/ssl"
	"github.com/innervoid/anubis/pkg/modules/sqli"
	"github.com/innervoid/anubis/pkg/modules/xss"
	"github.com/innervoid/anubis/pkg/report"
	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/state"
	"github.com/innervoid/anubis/pkg/utils"
)

// allModules returns the ordered list of all available scan modules.
// Modules are sorted roughly by speed (faster / lighter first).
func allModules() []scanner.Module {
	return []scanner.Module{
		portscan.New(),    // Level 1 — fast TCP connect
		sslmod.New(),      // Level 1 — TLS analysis
		headers.New(),     // Level 1 — HTTP header checks
		sensitive.New(),   // Level 1 — sensitive file discovery
		dns.New(),         // Level 2 — DNS enumeration
		sqli.New(),        // Level 2 — SQL injection detection
		xss.New(),         // Level 2 — XSS detection
		bruteforce.New(),  // Level 2 — default credential testing
		fingerprint.New(), // Level 3 — tech stack fingerprinting
	}
}

// dispatchScan handles the full scan lifecycle
func dispatchScan() error {
	cfg := buildConfig()

	if resume {
		return resumeScan(cfg)
	}
	if batch {
		return batchScan(cfg)
	}
	return runSingleScan(cfg)
}

// buildConfig maps CLI flags to ScanConfig
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

// runSingleScan executes a complete scan for one target
func runSingleScan(cfg scanner.ScanConfig) error {
	// Level 0 Baseline
	baselineMetrics, err := collectBaseline(cfg)
	if err != nil {
		utils.LogWarn("Baseline collection failed: %v — continuing without baseline", err)
	}

	// If a baseline file was provided, compare against it
	if cfg.BaselineFile != "" && baselineMetrics != nil {
		previous, err := baseline.LoadFromFile(cfg.BaselineFile)
		if err != nil {
			utils.LogWarn("Could not load baseline file: %v", err)
		} else {
			baseline.Compare(previous, baselineMetrics)
		}
	}

	// Save current baseline for future comparison
	if baselineMetrics != nil {
		if err := baseline.SaveToFile(baselineMetrics, "anubis_baseline.json"); err != nil {
			utils.LogDebug(cfg.Verbose, "Could not save baseline: %v", err)
		}
	}

	printPreScanInfo(cfg)

	// Build engine and run
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
	}

	// Remove checkpoint if it was left from a previous interrupted run
	if state.Exists() {
		state.Delete()
	}

	return nil
}

// resumeScan loads a checkpoint and continues scanning remaining modules
func resumeScan(cfg scanner.ScanConfig) error {
	if !state.Exists() {
		return fmt.Errorf("no checkpoint file found at %s — cannot resume", state.StateFile)
	}

	checkpoint, err := state.Load()
	if err != nil {
		return fmt.Errorf("resume: load checkpoint: %w", err)
	}

	utils.LogInfo("Resuming scan for target: %s", checkpoint.Target)
	utils.LogInfo("Previously completed:  %s", strings.Join(checkpoint.CompletedModules, ", "))
	utils.LogInfo("Remaining modules:     %s", strings.Join(checkpoint.RemainingModules, ", "))

	// Restore config from checkpoint; allow new CLI flags to override
	resumeCfg := checkpoint.Flags
	resumeCfg.Target = checkpoint.Target
	resumeCfg.Level = checkpoint.Level
	resumeCfg.Modules = checkpoint.RemainingModules

	engine := scanner.NewEngine(resumeCfg, allModules())
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("resume scan failed: %w", err)
	}

	// Merge with previously collected findings
	result.AllFindings = append(checkpoint.Findings, result.AllFindings...)

	report.PrintTerminalSummary(result)

	if err := report.Generate(result, resumeCfg.OutputFormat, resumeCfg.OutputFile, resumeCfg.ReportLevel); err != nil {
		utils.LogWarn("Report generation error: %v", err)
	}

	state.Delete()
	return nil
}

// batchScan reads targets from a file and scans each one sequentially
func batchScan(cfg scanner.ScanConfig) error {
	if cfg.BatchFile == "" {
		return fmt.Errorf("--batch-file is required with --batch")
	}

	targets, err := readTargetFile(cfg.BatchFile)
	if err != nil {
		return fmt.Errorf("batch: read targets: %w", err)
	}

	utils.LogInfo("Batch mode: %d targets loaded from %s", len(targets), cfg.BatchFile)

	for i, t := range targets {
		utils.PrintSeparator()
		utils.LogInfo("Batch [%d/%d]: scanning %s", i+1, len(targets), t)

		batchCfg := cfg
		batchCfg.Target = utils.NormalizeTarget(t)
		batchCfg.OutputFile = fmt.Sprintf("anubis_%s", sanitizeFilename(t))

		if err := runSingleScan(batchCfg); err != nil {
			utils.LogWarn("Scan failed for %s: %v", t, err)
		}
	}

	utils.LogSuccess("Batch scan complete: %d targets processed", len(targets))
	return nil
}

// collectBaseline runs the Level 0 baseline measurement
func collectBaseline(cfg scanner.ScanConfig) (*baseline.Metrics, error) {
	return baseline.Collect(cfg.Target, cfg.ShowBaselineProgress)
}

// printPreScanInfo prints a human-readable summary of the scan config
func printPreScanInfo(cfg scanner.ScanConfig) {
	utils.PrintSeparator()
	utils.LogInfo("Target:    %s", cfg.Target)
	utils.LogInfo("Level:     %d", cfg.Level)
	utils.LogInfo("Threads:   %d", cfg.Threads)
	utils.LogInfo("Timeout:   %ds", cfg.Timeout)
	utils.LogInfo("Rate:      %dms between requests", cfg.RateLimit)
	if cfg.ProxyURL != "" {
		utils.LogInfo("Proxy:     %s", cfg.ProxyURL)
	}
	if cfg.SSLBypass {
		utils.LogWarn("SSL bypass enabled — certificate errors will be ignored")
	}
	utils.PrintSeparator()
}

// readTargetFile reads a newline-separated list of targets, ignoring blank lines and comments
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

// sanitizeFilename replaces characters unsafe for file names
func sanitizeFilename(s string) string {
	r := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
		".", "_",
	)
	return r.Replace(s)
}
