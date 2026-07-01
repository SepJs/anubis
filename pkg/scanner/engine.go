// Package scanner implements the worker-pool scan engine with dynamic
// context cancellation, panic recovery, modular dispatch, and concurrency
// control via a bounded semaphore.
package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/SepJs/anubis/pkg/utils"
)

const timeLimitLevel1 = 5 * time.Minute

var crashLogger *log.Logger

func init() {
	f, err := os.OpenFile("crash.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		crashLogger = log.New(f, "[PANIC] ", log.LstdFlags|log.Lshortfile)
	}
}

func moduleTimeout(cfg ScanConfig) time.Duration {
	if cfg.Level == Level1 {
		return 4 * time.Minute
	}
	base := time.Duration(cfg.Timeout) * time.Second
	if base*4 > 15*time.Minute {
		return 15 * time.Minute
	}
	return base * 4
}

type Engine struct {
	cfg     ScanConfig
	modules []Module
	result  *AtomicResult
	mu      sync.Mutex

	findingsTotal    atomic.Int32
	modulesCompleted atomic.Int32
	modulesFailed    atomic.Int32
}

func NewEngine(cfg ScanConfig, modules []Module) *Engine {
	result := &ScanResult{
		Target:    cfg.Target,
		ScanLevel: cfg.Level,
		StartTime: time.Now(),
	}
	ar := NewAtomicResult()
	ar.Store(result)
	return &Engine{
		cfg:     cfg,
		modules: modules,
		result:  ar,
	}
}

func (e *Engine) Run() (*ScanResult, error) {
	utils.PrintSeparator()
	utils.LogInfo("Starting scan  target=%s  level=%d  threads=%d  ghost=%v",
		e.cfg.Target, e.cfg.Level, e.cfg.Threads, e.cfg.GhostMode)
	utils.PrintSeparator()

	eligible := e.eligibleModules()
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no modules eligible for scan level %d", e.cfg.Level)
	}

	threads := e.cfg.Threads
	if threads <= 0 {
		threads = 1
	}

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

	findingsCh := make(chan Finding, 4096)
	resultsCh := make(chan ModuleResult, len(eligible))
	printerDone := make(chan struct{})
	watcherDone := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		defer close(printerDone)
		for f := range findingsCh {
			r := e.result.Load()
			if r == nil {
				continue
			}
			e.mu.Lock()
			r.AllFindings = append(r.AllFindings, f)
			e.mu.Unlock()
			e.findingsTotal.Add(1)
			if !e.cfg.GhostMode {
				printFinding(f, e.cfg.Verbose)
			}
		}
	}()

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, mod := range eligible {
		select {
		case <-ctx.Done():
			utils.LogWarn("Context cancelled — skipping remaining modules")
			break
		default:
		}

		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					stack := debug.Stack()
					errMsg := fmt.Sprintf("module %s panicked: %v\n%s", m.Name(), r, stack)
					if crashLogger != nil {
						crashLogger.Println(errMsg)
					}
					fmt.Fprintf(os.Stderr, "CRASH: %s\n", errMsg)
				}
			}()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			modCtx, modCancel := context.WithTimeout(ctx, moduleTimeout(e.cfg))
			defer modCancel()

			mr := e.runModule(modCtx, m, findingsCh)
			resultsCh <- mr

			if mr.Status == "completed" {
				e.modulesCompleted.Add(1)
			} else {
				e.modulesFailed.Add(1)
			}
		}(mod)
	}

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

	wg.Wait()
	close(findingsCh)
	close(resultsCh)
	cancel()

	<-printerDone
	<-watcherDone

	for mr := range resultsCh {
		e.mu.Lock()
		r := e.result.Load()
		if r != nil {
			r.Modules = append(r.Modules, mr)
		}
		e.mu.Unlock()
	}

	e.finalize()
	return e.result.Load(), nil
}

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
				stack := debug.Stack()
				errMsg := fmt.Sprintf("module %s panicked: %v\n%s", m.Name(), r, stack)
				if crashLogger != nil {
					crashLogger.Println(errMsg)
				}
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
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
				int(e.findingsTotal.Load()))
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

	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Level() != eligible[j].Level() {
			return eligible[i].Level() < eligible[j].Level()
		}
		return eligible[i].Name() < eligible[j].Name()
	})

	return eligible
}

func (e *Engine) finalize() {
	r := e.result.Load()
	if r == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)

	summary := ScanSummary{
		BySeverity:   make(map[string]int),
		ByType:       make(map[string]int),
		ByConfidence: make(map[string]int),
	}
	var totalCVSS float64
	cvssCount := 0
	for _, f := range r.AllFindings {
		summary.TotalFindings++
		summary.BySeverity[string(f.Severity)]++
		summary.ByType[string(f.Type)]++
		summary.ByConfidence[string(f.Confidence)]++
		if f.CVSSScore > 0 {
			totalCVSS += f.CVSSScore
			cvssCount++
		}
	}
	if cvssCount > 0 {
		summary.CVSSAverage = totalCVSS / float64(cvssCount)
	}

	riskMap := map[string]float64{
		"CRITICAL": 10.0,
		"HIGH":     7.5,
		"MEDIUM":   5.0,
		"LOW":      2.5,
		"INFO":     0.0,
	}
	var riskScore float64
	for sev, count := range summary.BySeverity {
		riskScore += riskMap[sev] * float64(count)
	}
	if summary.TotalFindings > 0 {
		summary.RiskScore = riskScore / float64(summary.TotalFindings)
	}

	for _, mr := range r.Modules {
		summary.ModulesRun++
		switch mr.Status {
		case "completed":
			summary.ModulesCompleted++
		case "failed", "timeout":
			summary.ModulesFailed++
		}
	}
	r.Summary = summary
}

func (e *Engine) saveCheckpoint() {
	utils.LogInfo("Saving checkpoint to .anubis.state")
}

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
