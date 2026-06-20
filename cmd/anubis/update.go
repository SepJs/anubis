package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
)

// runCheckUpdate queries GitHub and reports whether a newer release exists.
// It never downloads or modifies anything — read-only by design, so it's
// safe to run in scripts/cron without risk of an unattended binary swap.
func runCheckUpdate() error {
	utils.LogInfo("Checking %s for the latest release...", version.ProjectURL)

	release, err := version.FetchLatest()
	if err != nil {
		// Network failure, rate limit, or no releases yet — all surfaced
		// as a plain error rather than silently claiming "up to date".
		return fmt.Errorf("check-update: %w", err)
	}

	if version.IsNewer(release.TagName) {
		utils.LogWarn("Update available: %s → %s", version.Info(), release.TagName)
		if release.Body != "" {
			fmt.Println()
			fmt.Println("Changelog:")
			fmt.Println(indent(release.Body, "  "))
		}
		fmt.Printf("\nRun 'anubis --update' to install, or visit:\n  %s\n", release.HTMLURL)
		return nil
	}

	utils.LogSuccess("You are running the latest version (%s)", version.Info())
	return nil
}

// runUpdate checks for a newer release, and if one exists, downloads the
// matching platform asset and replaces the currently running binary.
// Requires interactive confirmation unless the user has already opted out
// via the --yes-style flow below (kept conservative: always confirm, since
// this overwrites the binary the user is currently running).
func runUpdate() error {
	utils.LogInfo("Checking %s for the latest release...", version.ProjectURL)

	release, err := version.FetchLatest()
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	if !version.IsNewer(release.TagName) {
		utils.LogSuccess("Already up to date (%s)", version.Info())
		return nil
	}

	utils.LogWarn("New version found: %s → %s", version.Info(), release.TagName)

	asset, err := version.SelectAsset(release)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	utils.LogInfo("Matched asset: %s (%d bytes)", asset.Name, asset.Size)

	if !confirmUpdate() {
		utils.LogInfo("Update cancelled.")
		return nil
	}

	exePath, err := version.CurrentExecutablePath()
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	utils.LogInfo("Downloading and installing %s...", release.TagName)
	backupPath, err := version.Apply(asset, exePath)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	utils.LogSuccess("Updated to %s", release.TagName)
	utils.LogInfo("Previous binary backed up at: %s", backupPath)
	utils.LogInfo("Run 'anubis --version' to confirm.")
	return nil
}

// confirmUpdate asks the user to confirm before overwriting the running
// binary. This is a separate, minimal y/n prompt (not utils.AskYN) so the
// update path has zero dependency on the scan-oriented prompt helpers.
func confirmUpdate() bool {
	fmt.Print("[?] Replace the current binary now? (y/n): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// indent prefixes every line of s with the given prefix — used to format
// the GitHub release changelog body for terminal display.
func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
