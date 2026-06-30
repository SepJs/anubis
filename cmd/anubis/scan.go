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
	"github.com/SepJs/anubis/pkg/cfg"
	"github.com/SepJs/anubis/pkg/db"
	"github.com/SepJs/anubis/pkg/evasion"
	"github.com/SepJs/anubis/pkg/heuristic"
	"github.com/SepJs/anubis/pkg/profile"
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
	}
}

func dispatchScan() error {
	go backgroundUpdateCheck()

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

func backgroundUpdateCheck() {
	time.Sleep(500 * time.Millisecond)

	release, err := version.FetchLatest()
	if err != nil {
		return
	}
	if version.IsNewer(release.TagName) {
		fmt.Printf("\n  [!] Update available: %s → %s\n", version.Version, release.TagName)
		fmt.Printf("      Run 'anubis --update' or visit %s\n\n", release.HTMLURL)
	}
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
	utils.PrintSeparator()
	utils.LogInfo("Target:    %s", cfg.Target)
	utils.LogInfo("Level:     %d", cfg.Level)
	utils.LogInfo("Threads:   %d", cfg.Threads)
	utils.LogInfo("Timeout:   %ds", cfg.Timeout)
	utils.LogInfo("Rate:      %dms (%s strategy)", cfg.RateLimit, cfg.DelayStrategy)
	if cfg.GhostMode {
		utils.LogInfo("Ghost:     enabled")
	}
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
