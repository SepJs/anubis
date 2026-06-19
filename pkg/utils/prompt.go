package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// AskYN prompts the user for a yes/no answer, returns true for yes
func AskYN(question string) bool {
	LogPrompt("%s (y/n): ", question)
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		switch input {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			LogPrompt("Please enter y or n: ")
		}
	}
}

// AskChoice prompts for one of several single-character choices
// choices is a map of char -> description
func AskChoice(question string, choices map[string]string) string {
	LogPrompt("%s\n", question)
	for k, v := range choices {
		fmt.Printf("       (%s) %s\n", k, v)
	}
	LogPrompt("Your choice: ")

	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if _, ok := choices[input]; ok {
			return input
		}
		validKeys := make([]string, 0, len(choices))
		for k := range choices {
			validKeys = append(validKeys, k)
		}
		LogPrompt("Please enter one of [%s]: ", strings.Join(validKeys, "/"))
	}
}

// AskTimeLimitAction asks what to do when 5-min limit is hit
func AskTimeLimitAction() string {
	LogPrompt("5-minute limit reached. (c)omplete current module then stop, or (s)top immediately: ")
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "c" || input == "s" {
			return input
		}
		LogPrompt("Please enter c or s: ")
	}
}

// AskPartialResults asks whether to include partial findings
func AskPartialResults() bool {
	return AskYN("[?] Include partial findings in report?")
}

// AskSavePartial asks whether to save partial results on interrupt
func AskSavePartial() bool {
	return AskYN("[?] Save partial results before quitting?")
}

// AskBruteForce asks whether to continue despite protection detection
func AskBruteForce() bool {
	return AskYN("[?] Continue brute-force attempts despite protection detected?")
}

// AskBlocking asks what to do when target is blocking
func AskBlocking() string {
	return AskChoice(
		"[?] Target is blocking/throttling scanner. Options:",
		map[string]string{
			"r": "Retry with delays",
			"s": "Skip module",
			"q": "Quit",
		},
	)
}

// AskSSLBypass asks what to do when SSL validation fails
func AskSSLBypass() string {
	return AskChoice(
		"[?] SSL/TLS certificate validation failed.",
		map[string]string{
			"b": "Bypass validation with warning",
			"s": "Skip HTTPS scanning",
			"q": "Quit",
		},
	)
}

// AskContinueOrStop asks whether to continue scanning remaining modules
func AskContinueOrStop() string {
	return AskChoice(
		"[?] Continue scanning remaining modules, or stop here?",
		map[string]string{
			"c": "Continue scanning",
			"s": "Stop here",
		},
	)
}
