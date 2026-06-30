package main

import (
	"fmt"
	"os"
	"runtime/debug"
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

	Execute()
}
