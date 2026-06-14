package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/innervoid/anubis/pkg/requester"
	"github.com/innervoid/anubis/pkg/utils"
)

type Engine struct {
	cfg     ScanConfig
	modules []Module
	result  *ScanResult
	mu      sync.Mutex
	Client  *requester.AnubisClient
}

func NewEngine(cfg ScanConfig, modules []Module) *Engine {
	return &Engine{
		cfg:     cfg,
		modules: modules,
		Client:  requester.NewClient(),
		result: &ScanResult{
			Target:    cfg.Target,
			ScanLevel: cfg.Level,
			StartTime: time.Now(),
		},
	}
}

func (e *Engine) Run() (*ScanResult, error) {
	utils.PrintSeparator()
	utils.LogInfo("Starting scan: target=%s level=%d threads=%d", e.cfg.Target, e.cfg.Level, e.cfg.Threads)
	utils.PrintSeparator()

	eligible := e.eligibleModules()
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no modules eligible for level %d", e.cfg.Level)
	}

	findingsCh := make(chan Finding, 256)
	resultsCh := make(chan ModuleResult, len(eligible))
	
	go func() {
		for f := range findingsCh {
			e.mu.Lock()
			e.result.AllFindings = append(e.result.AllFindings, f)
			e.mu.Unlock()
			printFinding(f, e.cfg.Verbose)
		}
	}()

	sem := make(chan struct{}, e.cfg.Threads)
	var wg sync.WaitGroup
	
	for _, mod := range eligible {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			sem <- struct{}{}
			resultsCh <- e.runModule(m, findingsCh)
			<-sem
		}(mod)
	}

	wg.Wait()
	close(findingsCh)
	close(resultsCh)

	for mr := range resultsCh {
		e.mu.Lock()
		e.result.Modules = append(e.result.Modules, mr)
		e.mu.Unlock()
	}

	e.finalize()
	return e.result, nil
}

func (e *Engine) runModule(m Module, findings chan<- Finding) ModuleResult {
	mr := ModuleResult{ModuleName: m.Name(), StartTime: time.Now()}
	utils.LogInfo("[ %-20s ] Starting...", m.Name())
	
	err := m.Run(e.cfg, findings, e.Client)
	
	mr.EndTime = time.Now()
	if err != nil {
		mr.Status = "failed"
		mr.Error = err.Error()
	} else {
		mr.Status = "completed"
	}
	return mr
}

func (e *Engine) eligibleModules() []Module {
	var eligible []Module
	for _, m := range e.modules {
		if m.Level() <= e.cfg.Level {
			eligible = append(eligible, m)
		}
	}
	return eligible
}

func (e *Engine) finalize() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.result.EndTime = time.Now()
	e.result.Duration = e.result.EndTime.Sub(e.result.StartTime)
}

func printFinding(f Finding, verbose bool) {
	fmt.Printf("[!] %s: %s\n", f.Severity, f.Title)
}