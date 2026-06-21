package main

import (
	"fmt"
	"strings"

	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
)

// runCheckUpdate queries GitHub and reports whether a newer release exists.
// Read-only — never downloads or modifies anything.
func runCheckUpdate() error {
	utils.LogInfo("Checking %s for the latest release...", version.ProjectURL)

	release, err := version.FetchLatest()
	if err != nil {
		return fmt.Errorf("check-update: %w", err)
	}

	if version.IsNewer(release.TagName) {
		utils.LogWarn("Update available: v%s → %s", version.Version, release.TagName)
		if release.Body != "" {
			fmt.Println()
			fmt.Println("  Changelog:")
			for _, line := range strings.Split(strings.TrimRight(release.Body, "\n"), "\n") {
				fmt.Printf("    %s\n", line)
			}
		}
		fmt.Printf("\n  Run 'anubis --update' to install automatically.\n  Release: %s\n", release.HTMLURL)
		return nil
	}

	utils.LogSuccess("Already up to date (v%s)", version.Version)
	return nil
}

// runUpdate performs a fully automatic update: fetches latest release,
// downloads the matching binary, replaces the current executable, and
// re-execs so the new version continues with the same flags.
// No confirmation prompt — by passing --update the user already confirmed intent.
func runUpdate() error {
	return version.RunAutoUpdate()
}
