// Package main is the entry point for the Anubis security scanner. It
// registers the panic recovery handler, triggers the 24-hour-throttled
// background update check, and dispatches to the Cobra CLI command tree.
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/SepJs/anubis/pkg/version"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			errMsg := fmt.Sprintf("FATAL PANIC: %v\n%s\n", r, stack)
			os.WriteFile("crash.log", []byte(errMsg), 0644)
			fmt.Fprintf(os.Stderr, "CRASH: Anubis encountered a fatal error.\n")
			fmt.Fprintf(os.Stderr, "Details written to crash.log\n")
			os.Exit(1)
		}
	}()

	// Start the 24-hour-throttled background update check on every startup.
	// This runs in a separate goroutine and will not block startup or scanning.
	go version.BackgroundCheck()

	Execute()
}
