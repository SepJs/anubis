package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

const CurrentVersion = "1.0.1"
const VersionURL = "https://raw.githubusercontent.com/SepJS/anubis/main/version.txt"
const BinaryURL = "https://raw.githubusercontent.com/SepJS/anubis/main/anubis" // یا لینک ریلیز گیت‌هاب

// CheckAndPerformUpdate checks if a new version exists and updates silently
func CheckAndPerformUpdate() {
	// 1. Get latest version string from GitHub
	resp, err := http.Get(VersionURL)
	if err != nil {
		return // Silent return to not interrupt the user if there's no internet
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	latestVersion := strings.TrimSpace(string(body))

	// 2. If version matches, no need to update
	if latestVersion == CurrentVersion || latestVersion == "" {
		return
	}

	// 3. New version found! Download the new binary
	fmt.Printf("[*] New update found (%s). Updating Anubis automatically...\n", latestVersion)
	
	respBinary, err := http.Get(BinaryURL)
	if err != nil {
		return
	}
	defer respBinary.Body.Close()

	// 4. Find current running binary path (e.g., /usr/local/bin/anubis)
	currentPath, err := exec.LookPath(os.Args[0])
	if err != nil {
		currentPath = "/usr/local/bin/anubis" // Fallback
	}

	// 5. Create a temporary file to write the new binary safely
	tmpFile, err := os.CreateTemp("", "anubis_update")
	if err != nil {
		return
	}
	defer os.Remove(tmpFile.Name())

	_, err = io.Copy(tmpFile, respBinary.Body)
	if err != nil {
		return
	}
	tmpFile.Close()

	// 6. Make it executable
	os.Chmod(tmpFile.Name(), 0755)

	// 7. Replace the old binary with the new one (Needs sudo/root if installed globally)
	err = os.Rename(tmpFile.Name(), currentPath)
	if err != nil {
		// If rename fails (e.g. permission denied), we can try via shell or notify user
		return
	}

	fmt.Println("[+] Update completed successfully! Please rerun your command.")
	os.Exit(0)
}