package profile

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"time"
)

type Profiler struct {
	cpuFile      *os.File
	memFile      *os.File
	traceFile    *os.File
	cpuProfiling bool
	startTime    time.Time
}

func NewProfiler() *Profiler {
	return &Profiler{}
}

func (p *Profiler) StartCPU(path string) error {
	if path == "" {
		path = "anubis_cpu.prof"
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("profile: create cpu: %w", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return fmt.Errorf("profile: start cpu: %w", err)
	}
	p.cpuFile = f
	p.cpuProfiling = true
	p.startTime = time.Now()
	return nil
}

func (p *Profiler) StopCPU() error {
	if !p.cpuProfiling {
		return nil
	}
	pprof.StopCPUProfile()
	p.cpuProfiling = false
	if p.cpuFile != nil {
		p.cpuFile.Close()
		p.cpuFile = nil
	}
	return nil
}

func (p *Profiler) WriteMemProfile(path string) error {
	if path == "" {
		path = "anubis_mem.prof"
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("profile: create mem: %w", err)
	}
	defer f.Close()

	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("profile: write heap: %w", err)
	}
	return nil
}

func (p *Profiler) StartTrace(path string) error {
	if path == "" {
		path = "anubis_trace.out"
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("profile: create trace: %w", err)
	}
	if err := trace.Start(f); err != nil {
		f.Close()
		return fmt.Errorf("profile: start trace: %w", err)
	}
	p.traceFile = f
	return nil
}

func (p *Profiler) StopTrace() error {
	if p.traceFile == nil {
		return nil
	}
	trace.Stop()
	p.traceFile.Close()
	p.traceFile = nil
	return nil
}

func (p *Profiler) GenerateFlameGraph(outputPath string) error {
	return fmt.Errorf("flame graph generation requires `go tool pprof -http` and is not available in this build")
}

func (p *Profiler) PrintGoroutineStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Println("=== Goroutine Profile ===")
	fmt.Printf("Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Printf("CPU: %d cores\n", runtime.NumCPU())
	fmt.Printf("Heap Alloc: %d MB\n", m.Alloc/1024/1024)
	fmt.Printf("Heap Inuse: %d MB\n", m.HeapInuse/1024/1024)
	fmt.Printf("Stack Inuse: %d MB\n", m.StackInuse/1024/1024)
	fmt.Printf("GC Cycles: %d\n", m.NumGC)
	fmt.Printf("Pause Total: %d ms\n", m.PauseTotalNs/1000000)
	fmt.Println("========================")
}

func (p *Profiler) Duration() time.Duration {
	if p.startTime.IsZero() {
		return 0
	}
	return time.Since(p.startTime)
}
