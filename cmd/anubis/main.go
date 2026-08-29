// Package main is the entry point for the Anubis security scanner. It
// registers the panic recovery handler, triggers the 24-hour-throttled
// background update check, and dispatches to the Cobra CLI command tree.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/SepJs/anubis/pkg/version"
)

// crashLogPath returns a per-user cache location for crash logs,
// e.g. ~/.cache/anubis/crash.log on Linux.
// Falls back to the current directory if no cache dir can be resolved.
func crashLogPath() string {
	if base, err := os.UserCacheDir(); err == nil {
		dir := filepath.Join(base, "anubis")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return filepath.Join(dir, "crash.log")
		}
	}
	return "crash.log"
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			errMsg := fmt.Sprintf("FATAL PANIC: %v\n%s\n", r, stack)
			logPath := crashLogPath()
			_ = os.WriteFile(logPath, []byte(errMsg), 0o644)
			fmt.Fprintf(os.Stderr, "CRASH: Anubis encountered a fatal error.\n")
			fmt.Fprintf(os.Stderr, "Details written to %s\n", logPath)
			os.Exit(1)
		}
	}()

	// Start the 24-hour-throttled background update check on every startup.
	// This runs in a separate goroutine and will not block startup or scanning.
	go version.BackgroundCheck()

	Execute()
}
