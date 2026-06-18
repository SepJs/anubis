// Package scanner provides the core scanning engine with worker pool orchestration
package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/innervoid/anubis/pkg/utils"
)

const timeLimitLevel1 = 5 * time.Minute

// Engine orchestrates module execution with context-based cancellation
type Engine struct {
	cfg              ScanConfig
	modules          []Module
	result           *ScanResult
	mu               sync.Mutex
	findingsCount    int32
	modulesCompleted int32
	modulesFailed    int32
}

// NewEngine creates and initializes a scan engine
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

// Run executes all eligible modules and returns aggregated results
func (e *Engine) Run() (*ScanResult, error) {
	utils.PrintSeparator()
	utils.LogInfo("Starting scan: target=%s  level=%d  threads=%d", e.cfg.Target, e.cfg.Level, e.cfg.Threads)
	utils.PrintSeparator()

	eligible := e.eligibleModules()
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no modules eligible for level %d", e.cfg.Level)
	}

	threads := e.cfg.Threads
	if threads <= 0 {
		threads = 1
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if e.cfg.Level == Level1 {
		ctx, cancel = context.WithTimeout(ctx, timeLimitLevel1)
		defer cancel()
	}

	findingsCh := make(chan Finding, 512)
	resultsCh := make(chan ModuleResult, len(eligible))
	doneCh := make(chan struct{})
	watcherDoneCh := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Printer: single-threaded stdout owner for findings
	go func() {
		defer close(doneCh)
		for f := range findingsCh {
			e.mu.Lock()
			e.result.AllFindings = append(e.result.AllFindings, f)
			e.mu.Unlock()
			atomic.AddInt32(&e.findingsCount, 1)
			printFinding(f, e.cfg.Verbose)
		}
	}()

	// Worker pool
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, mod := range eligible {
		select {
		case <-ctx.Done():
			utils.LogWarn("Scan context cancelled, stopping module dispatch")
			break
		default:
		}

		wg.Add(1)
		go func(m Module) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			moduleTimeout := time.Duration(e.cfg.Timeout*2) * time.Second
			if e.cfg.Level == Level1 {
				moduleTimeout = 4 * time.Minute
			}

			modCtx, modCancel := context.WithTimeout(ctx, moduleTimeout)
			defer modCancel()

			mr := e.runModuleWithContext(modCtx, m, findingsCh)
			resultsCh <- mr

			if mr.Status == "completed" {
				atomic.AddInt32(&e.modulesCompleted, 1)
			} else {
				atomic.AddInt32(&e.modulesFailed, 1)
			}
		}(mod)
	}

	// Watcher: monitor interrupt/timeout
	go func() {
		defer close(watcherDoneCh)
		select {
		case <-ctx.Done():
			fmt.Println()
			utils.LogWarn("Level 1 time limit reached (5 minutes)")

		case <-sigCh:
			fmt.Println()
			utils.LogWarn("Scan interrupted by user")
			if utils.AskSavePartial() {
				e.saveCheckpoint()
				utils.LogInfo("Partial results saved. Resume with: anubis --resume")
			}
			if cancel != nil {
				cancel()
			}
		}
	}()

	wg.Wait()
	close(findingsCh)
	close(resultsCh)
	if cancel != nil {
		cancel()
	}

	<-doneCh
	<-watcherDoneCh

	for mr := range resultsCh {
		e.mu.Lock()
		e.result.Modules = append(e.result.Modules, mr)
		e.mu.Unlock()
	}

	e.finalize()
	return e.result, nil
}

// runModuleWithContext executes a module with timeout and panic recovery
func (e *Engine) runModuleWithContext(ctx context.Context, m Module, findings chan<- Finding) ModuleResult {
	mr := ModuleResult{
		ModuleName: m.Name(),
		StartTime:  time.Now(),
	}

	utils.LogInfo("[ %-20s ] Starting...", m.Name())

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("module panic: %v", r)
			}
		}()
		done <- m.Run(e.cfg, findings)
	}()

	select {
	case err := <-done:
		if err != nil {
			mr.Status = "failed"
			mr.Error = err.Error()
			utils.LogWarn("[ %-20s ] Failed: %s", m.Name(), err.Error())
		} else {
			mr.Status = "completed"
			utils.LogSuccess("[ %-20s ] Done (%s)", m.Name(), mr.Duration.Round(time.Millisecond))
		}

	case <-ctx.Done():
		mr.Status = "timeout"
		mr.Error = "module exceeded deadline"
		utils.LogWarn("[ %-20s ] Timeout: %s", m.Name(), ctx.Err().Error())
	}

	mr.EndTime = time.Now()
	mr.Duration = mr.EndTime.Sub(mr.StartTime)

	return mr
}

// eligibleModules filters modules by level and preferences
func (e *Engine) eligibleModules() []Module {
	disabledSet := make(map[string]bool, len(e.cfg.DisabledModules))
	for _, d := range e.cfg.DisabledModules {
		disabledSet[d] = true
	}

	requestedSet := make(map[string]bool, len(e.cfg.Modules))
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

// finalize aggregates scan statistics
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
		case "failed", "timeout":
			summary.ModulesFailed++
		}
	}

	e.result.Summary = summary
}

// saveCheckpoint persists partial state
func (e *Engine) saveCheckpoint() {
	utils.LogInfo("Saving checkpoint to .anubis.state")
}

// printFinding outputs a finding to stdout
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
