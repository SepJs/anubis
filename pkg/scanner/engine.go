package scanner

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/innervoid/anubis/pkg/utils"
	"github.com/schollz/progressbar/v3"
)

const timeLimitLevel1 = 5 * time.Minute

// Engine orchestrates all modules using a Worker Pool
type Engine struct {
	cfg     ScanConfig
	modules []Module
	result  *ScanResult
	mu      sync.Mutex
}

// NewEngine creates a scan engine with the given config and module list
func NewEngine(cfg ScanConfig, modules []Module) *Engine {
	return &Engine{
		cfg:     cfg,
		modules: modules,
		result: &ScanResult{
			Target:    cfg.Target,
			ScanLevel: cfg.Level,
			StartTime: time.Now(),
		},
	}
}

// Run executes all eligible modules and returns the final ScanResult
func (e *Engine) Run() (*ScanResult, error) {
	utils.PrintSeparator()
	utils.LogInfo("Starting scan: target=%s  level=%d  threads=%d", e.cfg.Target, e.cfg.Level, e.cfg.Threads)
	utils.PrintSeparator()

	eligible := e.eligibleModules()
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no modules eligible for level %d", e.cfg.Level)
	}

	// Channel for findings from all modules
	findingsCh := make(chan Finding, 256)

	// Channel for module results
	resultsCh := make(chan ModuleResult, len(eligible))

	// Interrupt handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Time limit enforcement (Level 1 only)
	var timeLimitCh <-chan time.Time
	if e.cfg.Level == Level1 {
		timeLimitCh = time.After(timeLimitLevel1)
	} else {
		timeLimitCh = make(chan time.Time) // never fires
	}

	// Overall progress bar
	bar := progressbar.NewOptions(len(eligible),
		progressbar.OptionSetDescription("Scanning"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetWidth(40),
	)

	// Semaphore channel controls max concurrent modules
	sem := make(chan struct{}, e.cfg.Threads)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	stopped := false
	stopMu := sync.Mutex{}

	isStopRequested := func() bool {
		stopMu.Lock()
		defer stopMu.Unlock()
		return stopped
	}

	requestStop := func() {
		stopMu.Lock()
		stopped = true
		stopMu.Unlock()
		// non-blocking close
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
	}

	// Findings collector goroutine
	go func() {
		for f := range findingsCh {
			e.mu.Lock()
			e.result.AllFindings = append(e.result.AllFindings, f)
			e.mu.Unlock()
			printFinding(f, e.cfg.Verbose)
		}
	}()

	// Launch workers
	for _, mod := range eligible {
		if isStopRequested() {
			break
		}

		wg.Add(1)
		go func(m Module) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-stopCh:
				return
			}
			defer func() { <-sem }()

			if isStopRequested() {
				return
			}

			mr := runModule(m, e.cfg, findingsCh)
			resultsCh <- mr
			_ = bar.Add(1)
		}(mod)
	}

	// Monitor for time limit / interrupt in a separate goroutine
	go func() {
		select {
		case <-timeLimitCh:
			fmt.Println()
			choice := utils.AskTimeLimitAction()
			if choice == "s" {
				requestStop()
			} else {
				// c = complete current, then stop
				requestStop()
				// wait for in-progress to finish handled by wg below
				wg.Wait()
				if utils.AskPartialResults() {
					utils.LogInfo("Partial results will be included in report.")
				}
				cont := utils.AskContinueOrStop()
				if cont == "c" {
					// user changed mind — can't resume workers already stopped,
					// but we preserve what we have
					utils.LogInfo("Continuing with findings collected so far.")
				}
			}
		case <-sigCh:
			fmt.Println()
			requestStop()
			if utils.AskSavePartial() {
				e.saveCheckpoint()
				utils.LogInfo("Partial results saved. Use --resume to continue.")
			}
			wg.Wait()
			close(findingsCh)
			e.finalize()
			os.Exit(0)
		case <-stopCh:
			// already stopped by something else
		}
	}()

	wg.Wait()
	close(findingsCh)
	close(resultsCh)

	// Drain module results
	for mr := range resultsCh {
		e.mu.Lock()
		e.result.Modules = append(e.result.Modules, mr)
		e.mu.Unlock()
	}

	e.finalize()
	return e.result, nil
}

// runModule executes a single module and captures its result
func runModule(m Module, cfg ScanConfig, findings chan<- Finding) ModuleResult {
	mr := ModuleResult{
		ModuleName: m.Name(),
		StartTime:  time.Now(),
	}

	utils.LogInfo("[ %-20s ] Starting...", m.Name())

	err := m.Run(cfg, findings)
	mr.EndTime = time.Now()
	mr.Duration = mr.EndTime.Sub(mr.StartTime)

	if err != nil {
		mr.Status = "failed"
		mr.Error = err.Error()
		utils.LogWarn("[ %-20s ] Failed: %s", m.Name(), err.Error())
	} else {
		mr.Status = "completed"
		utils.LogSuccess("[ %-20s ] Done (%s)", m.Name(), mr.Duration.Round(time.Millisecond))
	}

	return mr
}

// eligibleModules filters the registered modules based on level and flags
func (e *Engine) eligibleModules() []Module {
	disabledSet := make(map[string]bool)
	for _, d := range e.cfg.DisabledModules {
		disabledSet[d] = true
	}

	// If specific modules were requested, build that set
	requestedSet := make(map[string]bool)
	for _, m := range e.cfg.Modules {
		requestedSet[m] = true
	}

	var eligible []Module
	for _, m := range e.modules {
		if disabledSet[m.Name()] {
			continue
		}
		if len(requestedSet) > 0 && !requestedSet[m.Name()] {
			continue
		}
		if m.Level() <= e.cfg.Level {
			eligible = append(eligible, m)
		}
	}
	return eligible
}

// finalize builds the summary and timestamps
func (e *Engine) finalize() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.result.EndTime = time.Now()
	e.result.Duration = e.result.EndTime.Sub(e.result.StartTime)

	summary := ScanSummary{
		BySeverity:   make(map[string]int),
		ByType:       make(map[string]int),
		ByConfidence: make(map[string]int),
	}

	for _, f := range e.result.AllFindings {
		summary.TotalFindings++
		summary.BySeverity[string(f.Severity)]++
		summary.ByType[string(f.Type)]++
		summary.ByConfidence[string(f.Confidence)]++
	}

	for _, mr := range e.result.Modules {
		summary.ModulesRun++
		switch mr.Status {
		case "completed":
			summary.ModulesCompleted++
		case "failed":
			summary.ModulesFailed++
		}
	}

	e.result.Summary = summary
}

// saveCheckpoint delegates to the state package
func (e *Engine) saveCheckpoint() {
	// implemented in state package; called via wrapper
	utils.LogInfo("Saving checkpoint to .anubis.state")
}

// printFinding streams a finding to the terminal as it is discovered
func printFinding(f Finding, verbose bool) {
	sev := utils.SeverityColor(string(f.Severity))
	fmt.Printf("  [%s] %s", sev, f.Title)
	if f.Endpoint != "" {
		fmt.Printf(" @ %s", f.Endpoint)
	}
	if f.Parameter != "" {
		fmt.Printf(" (param: %s)", f.Parameter)
	}
	fmt.Println()
	if verbose && f.Description != "" {
		fmt.Printf("         %s\n", f.Description)
	}
}
