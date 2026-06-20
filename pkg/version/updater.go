// updater.go — downloads and installs a new Anubis binary in place.
// Asset naming convention matches the Makefile's build-all target:
//   anubis-linux-amd64, anubis-darwin-arm64, anubis-windows-amd64.exe, etc.
package version

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const downloadTimeout = 90 * time.Second

// SelectAsset finds the release asset matching the current OS and architecture.
// It expects assets named "anubis-<goos>-<goarch>[.exe]" — exactly what the
// Makefile's build-all target produces.
func SelectAsset(release *ReleaseInfo) (*ReleaseAsset, error) {
	if len(release.Assets) == 0 {
		return nil, fmt.Errorf("update: release %s has no downloadable assets", release.TagName)
	}

	goos := runtime.GOOS     // "linux", "darwin", "windows"
	goarch := runtime.GOARCH // "amd64", "arm64"
	want := fmt.Sprintf("anubis-%s-%s", goos, goarch)

	for i := range release.Assets {
		name := strings.ToLower(release.Assets[i].Name)
		if strings.HasPrefix(name, want) {
			return &release.Assets[i], nil
		}
	}

	return nil, fmt.Errorf(
		"update: no asset matched anubis-%s-%s among %d asset(s) in release %s — "+
			"check https://github.com/SepJs/anubis/releases/%s for available builds",
		goos, goarch, len(release.Assets), release.TagName, release.TagName,
	)
}

// Apply downloads the given asset and atomically replaces the binary at
// currentExePath. Backs up the old binary first; restores it automatically
// if the final rename fails.
func Apply(asset *ReleaseAsset, currentExePath string) (backupPath string, err error) {
	if asset.DownloadURL == "" {
		return "", fmt.Errorf("update: asset %q has no download URL", asset.Name)
	}

	dir := filepath.Dir(currentExePath)
	tmpPath := filepath.Join(dir, ".anubis-update-tmp")
	backupPath = filepath.Join(dir, ".anubis-previous")

	if err := downloadTo(asset.DownloadURL, tmpPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: download failed: %w", err)
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: chmod: %w", err)
	}

	// Back up current binary before replacing it
	if err := os.Rename(currentExePath, backupPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, currentExePath); err != nil {
		// Restore backup so the user isn't left without a binary
		_ = os.Rename(backupPath, currentExePath)
		return backupPath, fmt.Errorf("update: install failed, previous version restored: %w", err)
	}

	return backupPath, nil
}

// CurrentExecutablePath returns the path of the running binary, following symlinks.
func CurrentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("update: resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil // non-fatal, use unresolved path
	}
	return resolved, nil
}

// downloadTo streams url into destPath.
func downloadTo(url, destPath string) error {
	client := &http.Client{Timeout: downloadTimeout}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "anubis-scanner/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}
