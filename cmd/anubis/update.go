package main

import (
	"fmt"
	"strings"

	"github.com/SepJs/anubis/pkg/utils"
	"github.com/SepJs/anubis/pkg/version"
)

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

func runUpdate() error {
	return version.RunAutoUpdate()
}
