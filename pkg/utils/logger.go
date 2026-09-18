package utils

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

var SilentMode bool

const (
	ansiReset      = "\033[0m"
	ansiRed        = "\033[31m"
	ansiGreen      = "\033[32m"
	ansiYellow     = "\033[33m"
	ansiBlue       = "\033[34m"
	ansiMagenta    = "\033[35m"
	ansiCyan       = "\033[36m"
	ansiWhite      = "\033[37m"
	ansiBold       = "\033[1m"
	ansiDim        = "\033[2m"
	ansiUL         = "\033[4m"
	ansiHiWhite    = "\033[97m"
	ansiHiCyan     = "\033[96m"
	ansiHiGreen    = "\033[92m"
	ansiHiRed      = "\033[91m"
	ansiBgRed      = "\033[41;97;1m"
	ansiBgYellow   = "\033[43;30;1m"
	ansiBgBlue     = "\033[44;97;1m"
	ansiBgGreen    = "\033[42;30;1m"
	ansiBgMagenta  = "\033[45;97;1m"
)

func timestamp() string {
	return time.Now().Format("15:04:05")
}

func LogInfo(format string, args ...interface{}) {
	if SilentMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[*]%s %s\n", ansiDim, timestamp(), ansiReset, ansiCyan+ansiBold, ansiReset, msg)
}

func LogSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[+]%s %s\n", ansiDim, timestamp(), ansiReset, ansiHiGreen+ansiBold, ansiReset, msg)
}

func LogWarn(format string, args ...interface{}) {
	if SilentMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[!]%s %s\n", ansiDim, timestamp(), ansiReset, ansiYellow+ansiBold, ansiReset, msg)
}

func LogCritical(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[✗ CRITICAL]%s %s\n", ansiDim, timestamp(), ansiReset, ansiBgRed, ansiReset, msg)
}

func LogModule(module string, format string, args ...interface{}) {
	if SilentMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[%-11s]%s %s\n", ansiDim, timestamp(), ansiReset, ansiHiCyan+ansiBold, strings.ToUpper(module), ansiReset, msg)
}

func LogDebug(verbose bool, format string, args ...interface{}) {
	if !verbose || SilentMode {
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
	if SilentMode {
		return
	}
	fmt.Printf("%s%s%s%s\n", ansiHiWhite, ansiBold, ansiUL, ansiReset)
	fmt.Printf("%s%s%s\n", ansiBold, text, ansiReset)
}

func PrintSeparator() {
	if SilentMode {
		return
	}
	fmt.Println(ansiDim + "──────────────────────────────────────────────────────────────────────" + ansiReset)
}

func PrintBanner() {
	if SilentMode {
		return
	}
	banner := `
   █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
  ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
  ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
  ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
  ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝`

	fmt.Print(ansiHiRed + ansiBold + banner + ansiReset + "\n\n")
	fmt.Printf("  %s┌─────────────────────────────────────────────────────────────┐%s\n", ansiDim, ansiReset)
	line1 := fmt.Sprintf("Anubis Security Scanner v%s (%s/%s)", anubisVersion, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %s│%s  %s%-57s%s%s│%s\n", ansiDim, ansiReset, ansiHiWhite+ansiBold, line1, ansiReset, ansiDim, ansiReset)
	fmt.Printf("  %s│%s  %sAuthor :%s Vladimir Unknown    %sGitHub :%s github.com/SepJs/anubis  %s│%s\n",
		ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset)
	fmt.Printf("  %s│%s  %sEngine :%s Zero-CGO Static      %sDefense:%s Polymorphic Anti-WAF   %s│%s\n",
		ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset)
	fmt.Printf("  %s└─────────────────────────────────────────────────────────────┘%s\n\n", ansiDim, ansiReset)
}

func PrintDisclaimer() {
	if SilentMode {
		return
	}
	fmt.Printf("  %s[!] LEGAL NOTICE:%s For authorized penetration testing & security audits only.\n\n",
		ansiYellow+ansiBold, ansiReset)
}

func SeverityBadge(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return ansiBgRed + " CRITICAL " + ansiReset
	case "HIGH":
		return ansiBgYellow + " HIGH " + ansiReset
	case "MEDIUM":
		return ansiBgMagenta + " MEDIUM " + ansiReset
	case "LOW":
		return ansiBgGreen + " LOW " + ansiReset
	case "INFO":
		return ansiBgBlue + " INFO " + ansiReset
	default:
		return "[" + severity + "]"
	}
}

func SeverityColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return ansiHiRed + ansiBold + severity + ansiReset
	case "HIGH":
		return ansiYellow + ansiBold + severity + ansiReset
	case "MEDIUM":
		return ansiMagenta + ansiBold + severity + ansiReset
	case "LOW":
		return ansiHiGreen + severity + ansiReset
	case "INFO":
		return ansiHiCyan + severity + ansiReset
	default:
		return severity
	}
}

// anubisVersion is used by PrintBanner when the ldflag-injected
// pkg/version.Version is not available (avoids import cycles).
const anubisVersion = "2.6.0"
