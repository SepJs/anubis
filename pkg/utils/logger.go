package utils

import (
	"fmt"
	"os"
	"time"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiWhite  = "\033[37m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiUL     = "\033[4m"
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
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
`
	fmt.Print(ansiRed + ansiBold + banner + ansiReset)
	fmt.Println(ansiDim + "  Security Scanner — Authorized Use Only" + ansiReset)
	fmt.Printf("%s  v%s | Vladimir Unknown | github.com/SepJs/anubis%s\n\n", ansiDim, getVersion(), ansiReset)
}

func PrintDisclaimer() {
	fmt.Println(ansiYellow + ansiBold + "[!] DISCLAIMER: This tool is designed for authorized security testing only." + ansiReset)
	fmt.Println(ansiYellow + ansiBold + "[!] Unauthorized use against systems you do not own or have explicit" + ansiReset)
	fmt.Println(ansiYellow + ansiBold + "[!] permission to test is illegal and unethical." + ansiReset)
	fmt.Println(ansiYellow + ansiBold + "[!] The author assumes no liability for misuse or damage caused by this tool." + ansiReset)
	fmt.Println(ansiYellow + ansiBold + "[!] Use this tool only for legitimate and ethical purposes." + ansiReset)
	fmt.Println(ansiYellow + ansiBold + "[!] Compliance with applicable laws and regulations is the user's responsibility." + ansiReset)
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

func getVersion() string {
	data, err := os.ReadFile("version.txt")
	if err != nil {
		return "dev"
	}
	return string(data)
}
