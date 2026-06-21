// updater.go — automatic binary update without user prompts.
// Flow: FetchLatest → SelectAsset → Apply → re-exec with same args.
// The caller (cmd/anubis/update.go) is responsible for deciding *when*
// to call RunAutoUpdate; the functions here do the work unconditionally.
package version

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const downloadTimeout = 90 * time.Second

// SelectAsset finds the release asset matching the current OS and architecture.
// Asset naming must match Makefile build-all output: anubis-<goos>-<goarch>[.exe]
func SelectAsset(release *ReleaseInfo) (*ReleaseAsset, error) {
	if len(release.Assets) == 0 {
		return nil, fmt.Errorf("update: release %s has no downloadable assets", release.TagName)
	}

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	want := fmt.Sprintf("anubis-%s-%s", goos, goarch)

	for i := range release.Assets {
		name := strings.ToLower(release.Assets[i].Name)
		if strings.HasPrefix(name, want) {
			return &release.Assets[i], nil
		}
	}

	return nil, fmt.Errorf(
		"update: no asset matched anubis-%s-%s in release %s — "+
			"visit https://github.com/SepJs/anubis/releases/%s",
		goos, goarch, release.TagName, release.TagName,
	)
}

// Apply downloads the asset and atomically replaces the running binary.
// Returns backupPath (where the old binary was moved) on success.
// If anything fails after the backup rename, the old binary is restored.
func Apply(asset *ReleaseAsset, currentExePath string) (backupPath string, err error) {
	if asset.DownloadURL == "" {
		return "", fmt.Errorf("update: asset %q has no download URL", asset.Name)
	}

	dir := filepath.Dir(currentExePath)
	tmpPath := filepath.Join(dir, ".anubis-update-tmp")
	backupPath = filepath.Join(dir, ".anubis-previous")

	if err := downloadTo(asset.DownloadURL, tmpPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: download: %w", err)
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: chmod: %w", err)
	}

	if err := os.Rename(currentExePath, backupPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("update: backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, currentExePath); err != nil {
		_ = os.Rename(backupPath, currentExePath) // restore on failure
		return backupPath, fmt.Errorf("update: install failed, restored previous: %w", err)
	}

	return backupPath, nil
}

// Reexec re-executes the updated binary with the same arguments and
// environment as the current process. It replaces the current process
// image via exec(2) — if successful it never returns.
// On Windows exec(2) isn't available so it falls back to returning nil
// (caller should restart manually).
func Reexec(exePath string) error {
	args := os.Args // [0] = binary path, [1:] = original flags
	args[0] = exePath

	// syscall.Exec is exec(2) — replaces this process with the new binary.
	// Only available on Unix; on Windows this returns an error and we fall
	// through to the manual-restart message in the caller.
	return syscall.Exec(exePath, args, os.Environ())
}

// RunAutoUpdate is the single entry point for fully automatic updates.
// It fetches the latest release, compares versions, downloads if newer,
// replaces the binary, and re-execs — all without asking the user anything.
// Prints progress to stdout so the user knows what's happening.
// Returns nil if already up to date or if re-exec replaced the process.
// Returns an error only if something genuinely failed (network, disk, etc.).
func RunAutoUpdate() error {
	fmt.Printf("[*] Checking for updates at %s...\n", ProjectURL)

	release, err := FetchLatest()
	if err != nil {
		return fmt.Errorf("update check failed: %w", err)
	}

	if !IsNewer(release.TagName) {
		fmt.Printf("[✓] Already up to date (v%s)\n", Version)
		return nil
	}

	fmt.Printf("[+] New version found: %s → %s\n", Version, release.TagName)

	asset, err := SelectAsset(release)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Downloading %s (%d bytes)...\n", asset.Name, asset.Size)

	exePath, err := CurrentExecutablePath()
	if err != nil {
		return err
	}

	backupPath, err := Apply(asset, exePath)
	if err != nil {
		return err
	}

	fmt.Printf("[✓] Updated to %s — previous binary at %s\n", release.TagName, backupPath)
	fmt.Printf("[*] Restarting with updated binary...\n")

	// Re-exec: replaces this process with the new binary carrying the same
	// flags the user originally ran. On success, this never returns.
	if err := Reexec(exePath); err != nil {
		// Windows or other platform where exec(2) isn't available.
		fmt.Printf("[!] Auto-restart not supported on this platform — please re-run anubis manually.\n")
	}

	return nil
}

// CurrentExecutablePath returns the real path to the running binary.
func CurrentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("update: resolve executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil
	}
	return resolved, nil
}

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
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}
