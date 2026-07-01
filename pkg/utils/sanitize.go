package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Compiled regular expressions used by the sanitisation helpers.
var (
	urlSchemeRe = regexp.MustCompile(`^(https?|ftp|smtp)://`)
	hostRe      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	ipRe        = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	pathRe      = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\~\%\@\!\$\&\'\(\)\*\+\,\;\=\:\?]*$`)
)

// SanitizeTarget validates and normalises a target URL, ensuring it has a
// scheme and a valid hostname or IP address. Returns the cleansed URL or an
// error describing the issue.
func SanitizeTarget(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("empty target")
	}

	if !urlSchemeRe.MatchString(input) {
		input = "http://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}

	if u.Hostname() == "" {
		return "", fmt.Errorf("target has no hostname")
	}

	host := u.Hostname()
	if !hostRe.MatchString(host) && !ipRe.MatchString(host) {
		return "", fmt.Errorf("invalid hostname: %s", host)
	}

	u.Fragment = ""
	return u.String(), nil
}

func SanitizePath(input string) string {
	clean := pathRe.ReplaceAllString(input, "")
	return clean
}

func SanitizeFilename(input string) string {
	r := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_",
		"*", "_", "?", "_", "\"", "_",
		"<", "_", ">", "_", "|", "_",
		" ", "_",
	)
	return r.Replace(input)
}

func SanitizeLogMessage(msg string) string {
	re := regexp.MustCompile(`(?:https?://|socks5://)[^\s]+`)
	return re.ReplaceAllString(msg, "[REDACTED_URL]")
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d (must be 1-65535)", port)
	}
	return nil
}
