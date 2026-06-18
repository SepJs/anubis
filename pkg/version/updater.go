// updater.go contains the logic for downloading and installing a new Anubis
// binary in place. Kept separate from version.go (which only does read-only
// metadata queries) so the "this writes to disk" code is easy to find and audit.
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

// SelectAsset picks the release asset matching the current OS/architecture.
// Expected asset naming convention (matches the cross-compile targets in the
// Makefile's build-all target): anubis-<os>-<arch>[.exe]
func SelectAsset(release *ReleaseInfo) (*ReleaseAsset, error) {
	if len(release.Assets) == 0 {
		return nil, fmt.Errorf("update: release %s has no downloadable assets", release.TagName)
	}

	goos := runtime.GOOS   // "linux", "darwin", "windows"
	goarch := runtime.GOARCH // "amd64", "arm64"

	want := fmt.Sprintf("%s-%s", goos, goarch)

	for i := range release.Assets {
		name := strings.ToLower(release.Assets[i].Name)
		if strings.Contains(name, want) {
			return &release.Assets[i], nil
		}
	}

	return nil, fmt.Errorf(
		"update: no asset found matching this platform (%s/%s) among %d asset(s) — "+
			"the maintainer may not have published a build for your OS/arch yet",
		goos, goarch, len(release.Assets),
	)
}

// Apply downloads the given asset and atomically replaces the binary at
// currentExePath. On any failure after the download starts, it restores the
// original binary from backup rather than leaving the install half-done.
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
		return "", fmt.Errorf("update: chmod new binary: %w", err)
	}

	// Move current binary to backup before swapping in the new one, so a
	// failed rename below has something to restore.
	if err := os.Rename(currentExePath, backupPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, currentExePath); err != nil {
		// Best-effort restore — if this also fails the user is left without
		// a binary at currentExePath, but backupPath still has the old one.
		_ = os.Rename(backupPath, currentExePath)
		return backupPath, fmt.Errorf("update: install new binary failed, restored previous version: %w", err)
	}

	return backupPath, nil
}

// downloadTo streams the given URL to a local file path.
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
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing downloaded binary: %w", err)
	}

	return nil
}

// CurrentExecutablePath resolves the path to the running binary, following
// symlinks so the backup/replace logic operates on the real file.
func CurrentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("update: could not resolve own executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		// Not fatal — fall back to the unresolved path.
		return exe, nil
	}
	return resolved, nil
}
