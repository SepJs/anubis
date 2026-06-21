package utils

import (
	"fmt"
	"time"

	"github.com/SepJs/anubis/pkg/version"
	"github.com/fatih/color"
)

var (
	colorInfo     = color.New(color.FgCyan, color.Bold)
	colorSuccess  = color.New(color.FgGreen, color.Bold)
	colorWarn     = color.New(color.FgYellow, color.Bold)
	colorCritical = color.New(color.FgRed, color.Bold)
	colorDim      = color.New(color.FgWhite)
	colorPrompt   = color.New(color.FgMagenta, color.Bold)
	colorHeader   = color.New(color.FgHiWhite, color.Bold, color.Underline)
)

type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelWarn
	LevelCritical
	LevelSuccess
	LevelDebug
)

func timestamp() string {
	return time.Now().Format("15:04:05")
}

func LogInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	colorInfo.Printf("[%s] [INFO] ", timestamp())
	fmt.Println(msg)
}

func LogSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	colorSuccess.Printf("[%s] [+] ", timestamp())
	fmt.Println(msg)
}

func LogWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	colorWarn.Printf("[%s] [!] ", timestamp())
	fmt.Println(msg)
}

func LogCritical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	colorCritical.Printf("[%s] [CRITICAL] ", timestamp())
	fmt.Println(msg)
}

func LogDebug(verbose bool, format string, args ...interface{}) {
	if !verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	colorDim.Printf("[%s] [DEBUG] %s\n", timestamp(), msg)
}

func LogPrompt(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	colorPrompt.Printf("[?] %s", msg)
}

func PrintHeader(text string) {
	colorHeader.Println(text)
}

func PrintSeparator() {
	colorDim.Println("─────────────────────────────────────────────────────────────")
}

func PrintBanner() {
	banner := `
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
`
	colorCritical.Println(banner)
	colorDim.Println("  Security Scanner — Authorized Use Only")
	colorDim.Printf("  v%s | Vladimir Unknown | github.com/SepJs/anubis\n\n", version.Version)
}

func PrintDisclaimer() {
	colorWarn.Println("[!] DISCLAIMER: This tool is designed for authorized security testing only.")
	colorWarn.Println("[!] Unauthorized use against systems you do not own or have explicit")
	colorWarn.Println("[!] permission to test is illegal and unethical.")
	colorWarn.Println("[!] The author assumes no liability for misuse or damage caused by this tool.")
	colorWarn.Println("[!] Use this tool only for legitimate and ethical purposes.")
	colorWarn.Println("[!] Compliance with applicable laws and regulations is the user's responsibility.")
	fmt.Println()
}

// SeverityColor returns a colored string for a severity level
func SeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return colorCritical.Sprint(severity)
	case "HIGH":
		return colorWarn.Sprint(severity)
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint(severity)
	case "LOW":
		return colorInfo.Sprint(severity)
	case "INFO":
		return colorDim.Sprint(severity)
	default:
		return severity
	}
}
