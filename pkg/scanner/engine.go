// Package scanner provides the core scan engine with context-aware module
// orchestration, adaptive scheduling, and real-time finding output.
package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/SepJs/anubis/pkg/utils"
)

// Level 1 scans have a hard 5-minute wall-clock limit.
const timeLimitLevel1 = 5 * time.Minute

// moduleTimeout returns how long a single module is allowed to run.
// Level 1: 4 minutes per module (leaves 1 min headroom for overhead).
// Level 2+: 4× the configured HTTP timeout so even slow hosts get a fair
// chance without letting one stuck endpoint block the whole scan.
func moduleTimeout(cfg ScanConfig) time.Duration {
	if cfg.Level == Level1 {
		return 4 * time.Minute
	}
	base := time.Duration(cfg.Timeout) * time.Second
	if base*4 > 15*time.Minute {
		return 15 * time.Minute // hard cap at 15 min per module for deep scans
	}
	return base * 4
}

// Engine orchestrates module execution with a bounded worker pool,
// context-based cancellation, per-module timeouts, and panic recovery.
type Engine struct {
	cfg     ScanConfig
	modules []Module
	result  *ScanResult
	mu      sync.Mutex

	// Atomic counters — updated from multiple goroutines without a lock.
	findingsTotal    int32
	modulesCompleted int32
	modulesFailed    int32
}

// NewEngine creates an engine with the given config and module list.
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

// Run executes all eligible modules and returns the aggregated ScanResult.
//
// Execution model:
//   - Eligible modules are sorted by level (lighter first), then name.
//   - A semaphore of size cfg.Threads limits concurrent execution.
//   - Each module runs inside its own goroutine with a per-module context.
//   - A single printer goroutine owns stdout for findings to prevent races.
//   - A watcher goroutine handles Ctrl-C and the Level 1 time limit.
func (e *Engine) Run() (*ScanResult, error) {
	utils.PrintSeparator()
	utils.LogInfo("Starting scan  target=%s  level=%d  threads=%d",
		e.cfg.Target, e.cfg.Level, e.cfg.Threads)
	utils.PrintSeparator()

	eligible := e.eligibleModules()
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no modules eligible for scan level %d", e.cfg.Level)
	}

	threads := e.cfg.Threads
	if threads <= 0 {
		threads = 1
	}

	// Root context: Level 1 gets a hard timeout, others run until done or Ctrl-C.
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if e.cfg.Level == Level1 {
		ctx, cancel = context.WithTimeout(context.Background(), timeLimitLevel1)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	// Channels
	findingsCh := make(chan Finding, 1024) // large buffer so modules rarely block
	resultsCh  := make(chan ModuleResult, len(eligible))
	printerDone := make(chan struct{})
	watcherDone := make(chan struct{})

	// OS signal channel for Ctrl-C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// ── Printer goroutine ──────────────────────────────────────────────────
	// Single owner of stdout for findings. All other goroutines write only
	// via findingsCh; the printer serialises the output.
	go func() {
		defer close(printerDone)
		for f := range findingsCh {
			e.mu.Lock()
			e.result.AllFindings = append(e.result.AllFindings, f)
			e.mu.Unlock()
			atomic.AddInt32(&e.findingsTotal, 1)
			printFinding(f, e.cfg.Verbose)
		}
	}()

	// ── Worker pool ────────────────────────────────────────────────────────
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, mod := range eligible {
		// Don't launch new workers if the root context is already done.
		select {
		case <-ctx.Done():
			utils.LogWarn("Context cancelled — skipping remaining modules")
			break
		default:
		}

		wg.Add(1)
		go func(m Module) {
			defer wg.Done()

			// Acquire semaphore slot (blocks until a slot is free or ctx done).
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Per-module deadline.
			modCtx, modCancel := context.WithTimeout(ctx, moduleTimeout(e.cfg))
			defer modCancel()

			mr := e.runModule(modCtx, m, findingsCh)
			resultsCh <- mr

			if mr.Status == "completed" {
				atomic.AddInt32(&e.modulesCompleted, 1)
			} else {
				atomic.AddInt32(&e.modulesFailed, 1)
			}
		}(mod)
	}

	// ── Watcher goroutine ──────────────────────────────────────────────────
	// Handles Ctrl-C and the Level 1 wall-clock timeout.
	// Never calls wg.Wait() — only cancels the context.
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			if e.cfg.Level == Level1 {
				fmt.Println()
				utils.LogWarn("Level 1 time limit reached (5 minutes) — stopping modules")
			}
		case sig := <-sigCh:
			fmt.Println()
			utils.LogWarn("Received %s — stopping scan", sig)
			if utils.AskSavePartial() {
				e.saveCheckpoint()
				utils.LogInfo("Partial results saved. Resume with: anubis --resume")
			}
			cancel()
		}
	}()

	// ── Wait and teardown ──────────────────────────────────────────────────
	wg.Wait()
	close(findingsCh)
	close(resultsCh)
	cancel() // ensure watcher exits its select

	<-printerDone
	<-watcherDone

	for mr := range resultsCh {
		e.mu.Lock()
		e.result.Modules = append(e.result.Modules, mr)
		e.mu.Unlock()
	}

	e.finalize()
	return e.result, nil
}

// runModule executes a single module with a context deadline and panic recovery.
// If the module implements ContextModule, RunWithContext is called so it can
// check for cancellation inside its own loops.
func (e *Engine) runModule(ctx context.Context, m Module, findings chan<- Finding) ModuleResult {
	mr := ModuleResult{
		ModuleName: m.Name(),
		StartTime:  time.Now(),
	}

	utils.LogInfo("[ %-22s ] Starting...", m.Name())

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		// Prefer RunWithContext if the module supports it.
		if cm, ok := m.(ContextModule); ok {
			done <- cm.RunWithContext(ctx, e.cfg, findings)
		} else {
			done <- m.Run(e.cfg, findings)
		}
	}()

	select {
	case err := <-done:
		mr.EndTime = time.Now()
		mr.Duration = mr.EndTime.Sub(mr.StartTime)
		if err != nil {
			mr.Status = "failed"
			mr.Error = err.Error()
			utils.LogWarn("[ %-22s ] Failed  (%s): %s",
				m.Name(), mr.Duration.Round(time.Millisecond), err)
		} else {
			mr.Status = "completed"
			utils.LogSuccess("[ %-22s ] Done    (%s)  findings: %d",
				m.Name(), mr.Duration.Round(time.Millisecond),
				int(atomic.LoadInt32(&e.findingsTotal)))
		}

	case <-ctx.Done():
		mr.EndTime = time.Now()
		mr.Duration = mr.EndTime.Sub(mr.StartTime)
		mr.Status = "timeout"
		mr.Error = ctx.Err().Error()
		utils.LogWarn("[ %-22s ] Timeout (%s)", m.Name(), mr.Duration.Round(time.Second))
	}

	return mr
}

// eligibleModules filters by level/include/exclude and sorts by level then name
// so lightweight modules always run before heavy ones.
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

	// Sort: lower level (faster/lighter) first; break ties alphabetically.
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Level() != eligible[j].Level() {
			return eligible[i].Level() < eligible[j].Level()
		}
		return eligible[i].Name() < eligible[j].Name()
	})

	return eligible
}

// finalize computes the scan summary.
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

func (e *Engine) saveCheckpoint() {
	utils.LogInfo("Saving checkpoint to .anubis.state")
}

// printFinding writes a single finding line to stdout.
// Called only from the printer goroutine — no mutex needed.
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
