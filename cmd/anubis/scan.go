package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SepJs/anubis/pkg/baseline"
	"github.com/SepJs/anubis/pkg/discovery"
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
	"github.com/SepJs/anubis/pkg/cfg"
	"github.com/SepJs/anubis/pkg/db"
	"github.com/SepJs/anubis/pkg/evasion"
	"github.com/SepJs/anubis/pkg/heuristic"
	"github.com/SepJs/anubis/pkg/profile"
	lfimod "github.com/SepJs/anubis/pkg/modules/lfi"
	openredirect "github.com/SepJs/anubis/pkg/modules/openredirect"
	sstimod "github.com/SepJs/anubis/pkg/modules/ssti"
	templatengine "github.com/SepJs/anubis/pkg/templates"
)

const reportsDir = "reports"

var (
	historyDB   *db.HistoryDB
	heuristicEngine *heuristic.HeuristicEngine
	evasionEngine  *evasion.JitterEngine
	profiler       *profile.Profiler
)

func allModules() []scanner.Module {
	return []scanner.Module{
		portscan.New(),
		sslmod.New(),
		headers.New(),
		sensitive.New(),
		dns.New(),
		sqli.New(),
		xss.New(),
		bruteforce.New(),
		fingerprint.New(),
		lfimod.New(),
		sstimod.New(),
		openredirect.New(),
	}
}

func dispatchScan() error {

	if profileMode {
		profiler = profile.NewProfiler()
		if err := profiler.StartCPU("anubis_cpu.prof"); err != nil {
			utils.LogWarn("Profile: %v", err)
		}
		if err := profiler.StartTrace("anubis_trace.out"); err != nil {
			utils.LogWarn("Trace: %v", err)
		}
		profiler.PrintGoroutineStats()
	}

	heuristicEngine = heuristic.NewHeuristicEngine()
	evasionEngine = evasion.NewJitterEngine()

	if configFile != "" {
		cfgData, err := cfg.Load(configFile)
		if err != nil {
			utils.LogWarn("Config load failed: %v — using defaults", err)
		} else {
			utils.LogInfo("Loaded configuration from %s", configFile)
			if cfgData.Database.Enabled {
				var err error
				historyDB, err = db.NewHistoryDB(
					cfgData.Database.Path,
					cfgData.Database.Encrypt,
					cfgData.Database.Passkey,
				)
				if err != nil {
					utils.LogWarn("Database init failed: %v — continuing without history", err)
				}
			}
		}
	}

	if historyDB == nil {
		historyDB, _ = db.NewHistoryDB("anubis_history.db", false, "")
	}

	scanCfg := buildConfig()

	if resume {
		return resumeScan(scanCfg)
	}
	if batch {
		return batchScan(scanCfg)
	}
	return runSingleScan(scanCfg)
}

func buildConfig() scanner.ScanConfig {
	cfg := scanner.ScanConfig{
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
		GhostMode:            ghostMode,
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
	return cfg
}

func ensureReportsDir() error {
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return fmt.Errorf("cannot create reports directory %q: %w", reportsDir, err)
	}
	return nil
}

func resolveOutputFile(cfg scanner.ScanConfig) string {
	if cfg.OutputFile != "" {
		if filepath.Dir(cfg.OutputFile) == "." {
			return filepath.Join(reportsDir, cfg.OutputFile)
		}
		return cfg.OutputFile
	}
	host := sanitizeFilename(cfg.Target)
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(reportsDir, fmt.Sprintf("anubis_%s_%s", host, ts))
}

func runSingleScan(cfg scanner.ScanConfig) error {
	if err := ensureReportsDir(); err != nil {
		utils.LogWarn("%v", err)
	}

	cfg.OutputFile = resolveOutputFile(cfg)

	baselineMetrics, err := collectBaseline(cfg)
	if err != nil {
		utils.LogWarn("Baseline collection failed: %v — continuing without baseline", err)
	}

	if cfg.BaselineFile != "" && baselineMetrics != nil {
		previous, err := baseline.LoadFromFile(cfg.BaselineFile)
		if err != nil {
			utils.LogWarn("Could not load baseline file: %v", err)
		} else {
			baseline.Compare(previous, baselineMetrics)
		}
	}

	if baselineMetrics != nil {
		bPath := filepath.Join(reportsDir, "anubis_baseline.json")
		if err := baseline.SaveToFile(baselineMetrics, bPath); err != nil {
			utils.LogDebug(cfg.Verbose, "Could not save baseline: %v", err)
		}
	}

	if crawl {
		ccfg := discovery.CrawlerConfig{
			Target:        cfg.Target,
			MaxDepth:      crawlDepth,
			MaxPages:      crawlMaxPages,
			Timeout:       time.Duration(cfg.Timeout) * time.Second,
			UserAgent:     cfg.UserAgent,
			SSLBypass:     cfg.SSLBypass,
			ProxyURL:      cfg.ProxyURL,
			RespectLimits: cfg.RespectLimits,
			Verbose:       cfg.Verbose,
		}
		c, err := discovery.NewCrawler(ccfg)
		if err != nil {
			utils.LogWarn("Crawler init error: %v", err)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			discovered := c.Crawl(ctx)
			cancel()
			cfg.Endpoints = append(cfg.Endpoints, discovered...)
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

	heuristicResults := heuristicEngine.AnalyzeAll(result.AllFindings)
	utils.LogDebug(cfg.Verbose, "Heuristic analysis: %d findings evaluated", len(heuristicResults))

	for i, hr := range heuristicResults {
		if i < len(result.AllFindings) {
			result.AllFindings[i].Likelihood = fmt.Sprintf("%.2f", hr.Likelihood)
		}
	}

// Custom YAML templates (--templates DIR) — appended to main findings.
	if templatesDir != "" {
		te, terr := templatengine.NewEngine(templatesDir)
		if terr != nil {
			utils.LogWarn("template: load error: %v", terr)
		} else if te.Count() > 0 {
			utils.LogInfo("Templates: running %d custom check(s)...", te.Count())
			tch := make(chan scanner.Finding, 64)
			go func() {
				defer close(tch)
				if rerr := te.Run(cfg, tch); rerr != nil {
					utils.LogWarn("template: run error: %v", rerr)
				}
			}()
			for f := range tch {
				result.AllFindings = append(result.AllFindings, f)
			}
			utils.LogSuccess("Templates: custom checks complete")
		}
	}
	
	if historyDB != nil {
		if _, err := historyDB.SaveScan(result); err != nil {
			utils.LogWarn("Failed to save scan history: %v", err)
		}
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

	if profiler != nil {
		profiler.StopCPU()
		profiler.StopTrace()
		profiler.WriteMemProfile("anubis_mem.prof")
		profiler.PrintGoroutineStats()
		utils.LogSuccess("Profile data saved: anubis_cpu.prof, anubis_mem.prof, anubis_trace.out")
	}

	if historyDB != nil {
		historyDB.Close()
	}

	return nil
}

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

	result.AllFindings = append(checkpoint.Findings, result.AllFindings...)

	if historyDB != nil {
		historyDB.SaveScan(result)
	}

	report.PrintTerminalSummary(result)

	if err := report.Generate(result, resumeCfg.OutputFormat, resumeCfg.OutputFile, resumeCfg.ReportLevel); err != nil {
		utils.LogWarn("Report generation error: %v", err)
	}

	state.Delete()
	return nil
}

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
		batchCfg.OutputFile = ""

		if err := runSingleScan(batchCfg); err != nil {
			utils.LogWarn("Scan failed for %s: %v", t, err)
		}
	}

	utils.LogSuccess("Batch complete: %d targets processed", len(targets))
	return nil
}

func collectBaseline(cfg scanner.ScanConfig) (*baseline.Metrics, error) {
	return baseline.Collect(cfg.Target, cfg.ShowBaselineProgress)
}

func printPreScanInfo(cfg scanner.ScanConfig) {
	if utils.SilentMode {
		return
	}
	dim := "\033[2m"
	bold := "\033[1m"
	reset := "\033[0m"
	cyan := "\033[36m"
	hiWhite := "\033[97m"

	fmt.Println()
	fmt.Printf("  %s┌── SCAN PROFILE & TARGET CONFIGURATION ──────────────────────────┐%s\n", dim, reset)
	fmt.Printf("  %s│%s  %sTarget   :%s %s%-51s%s%s│%s\n", dim, reset, cyan+bold, reset, bold+hiWhite, cfg.Target, reset, dim, reset)

	lvlDesc := "Level 1 (Passive Reconnaissance & Headers)"
	if cfg.Level == 2 {
		lvlDesc = "Level 2 (Active Vulnerability & Injection Audit)"
	} else if cfg.Level == 3 {
		lvlDesc = "Level 3 (Aggressive Exhaustive Deep Scan)"
	}
	fmt.Printf("  %s│%s  %sProfile  :%s %-51s%s│%s\n", dim, reset, cyan+bold, reset, lvlDesc, dim, reset)
	fmt.Printf("  %s│%s  %sEngine   :%s %d Workers | Timeout: %ds | Rate: %dms%-18s%s│%s\n",
		dim, reset, cyan+bold, reset, cfg.Threads, cfg.Timeout, cfg.RateLimit, "", dim, reset)

	stealth := fmt.Sprintf("%s strategy", cfg.DelayStrategy)
	if cfg.GhostMode {
		stealth = fmt.Sprintf("Ghost Mode (Polymorphic Anti-WAF, %s)", cfg.DelayStrategy)
	}
	fmt.Printf("  %s│%s  %sEvasion  :%s %-51s%s│%s\n", dim, reset, cyan+bold, reset, stealth, dim, reset)

	if len(cfg.Endpoints) > 0 {
		fmt.Printf("  %s│%s  %sEndpoints:%s %-51s%s│%s\n", dim, reset, cyan+bold, reset,
			fmt.Sprintf("%d target URIs mapped for audit", len(cfg.Endpoints)), dim, reset)
	}
	if cfg.ProxyURL != "" {
		fmt.Printf("  %s│%s  %sProxy    :%s %-51s%s│%s\n", dim, reset, cyan+bold, reset, cfg.ProxyURL, dim, reset)
	}
	fmt.Printf("  %s│%s  %sOutput   :%s %-51s%s│%s\n", dim, reset, cyan+bold, reset,
		fmt.Sprintf("%s (%s)", cfg.OutputFile, cfg.OutputFormat), dim, reset)
	fmt.Printf("  %s└──────────────────────────────────────────────────────────────────┘%s\n\n", dim, reset)
}

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
