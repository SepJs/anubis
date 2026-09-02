package utils

import (
	"fmt"
	"time"
)

const (
	ansiReset   = "\033[0m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiCyan    = "\033[36m"
	ansiWhite   = "\033[37m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiUL      = "\033[4m"
	ansiHiWhite = "\033[97m"
)

func timestamp() string {
	return time.Now().Format("15:04:05")
}

func LogInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [INFO]%s %s\n", ansiCyan+ansiBold, timestamp(), ansiReset, msg)
}

func LogSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [+]%s %s\n", ansiGreen+ansiBold, timestamp(), ansiReset, msg)
}

func LogWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [!]%s %s\n", ansiYellow+ansiBold, timestamp(), ansiReset, msg)
}

func LogCritical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [CRITICAL]%s %s\n", ansiRed+ansiBold, timestamp(), ansiReset, msg)
}

func LogDebug(verbose bool, format string, args ...interface{}) {
	if !verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [DEBUG]%s %s\n", ansiDim, timestamp(), ansiReset, msg)
}

func LogPrompt(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[?]%s %s", ansiBlue+ansiBold, ansiReset, msg)
}

func PrintHeader(text string) {
	fmt.Printf("%s%s%s%s\n", ansiHiWhite, ansiBold, ansiUL, ansiReset)
	fmt.Printf("%s%s%s\n", ansiBold, text, ansiReset)
}

func PrintSeparator() {
	fmt.Println(ansiDim + "─────────────────────────────────────────────────────────────" + ansiReset)
}

func PrintBanner() {
	banner := `
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝`
	fmt.Print(ansiRed + ansiBold + banner + ansiReset)
	fmt.Println()
	fmt.Println(ansiDim + "  ────────────────────────────────────────────────────────────" + ansiReset)
	fmt.Printf("%s  Author  : vladimir_unknown%s\n", ansiHiWhite+ansiBold, ansiReset)
	fmt.Printf("%s  Project : github.com/SepJs/anubis%s\n", ansiDim, ansiReset)
	fmt.Printf("%s  Version : v%s%s\n", ansiDim, anubisVersion, ansiReset)
	fmt.Println(ansiDim + "  ────────────────────────────────────────────────────────────" + ansiReset)
	fmt.Println()
}

func PrintDisclaimer() {
	fmt.Println(ansiYellow + ansiBold + "[!] DISCLAIMER:" + ansiReset)
	fmt.Println(ansiYellow + "    This tool is for EDUCATIONAL purposes only." + ansiReset)
	fmt.Println(ansiYellow + "    If anything goes wrong, it is on you — the author" + ansiReset)
	fmt.Println(ansiYellow + "    assumes no responsibility for any damage or misuse." + ansiReset)
	fmt.Println(ansiYellow + "    Use only against systems you own or have permission to test." + ansiReset)
	fmt.Println()
}

func SeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return ansiRed + ansiBold + severity + ansiReset
	case "HIGH":
		return ansiYellow + ansiBold + severity + ansiReset
	case "MEDIUM":
		return ansiYellow + severity + ansiReset
	case "LOW":
		return ansiBlue + severity + ansiReset
	case "INFO":
		return ansiDim + severity + ansiReset
	default:
		return severity
	}
}

// anubisVersion is used by PrintBanner when the ldflag-injected
// pkg/version.Version is not available (avoids import cycles).
const anubisVersion = "2.5.2"
