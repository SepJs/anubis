package version

import (
	"crypto/sha256"
	"encoding/hex"
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

	if asset.Checksum != "" {
		data, err := os.ReadFile(tmpPath)
		if err != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("update: read downloaded file: %w", err)
		}
		if !VerifyChecksum(data, asset.Checksum) {
			os.Remove(tmpPath)
			return "", fmt.Errorf("update: checksum mismatch — possible corruption or tampering")
		}
		fmt.Printf("[✓] Checksum verified (%s)\n", asset.Checksum[:16]+"...")
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
		_ = os.Rename(backupPath, currentExePath)
		return backupPath, fmt.Errorf("update: install failed, restored previous: %w", err)
	}

	return backupPath, nil
}

func Reexec(exePath string) error {
	args := os.Args
	args[0] = exePath
	return syscall.Exec(exePath, args, os.Environ())
}

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

	if err := Reexec(exePath); err != nil {
		fmt.Printf("[!] Auto-restart not supported on this platform — please re-run anubis manually.\n")
	}

	return nil
}

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

	h := sha256.New()
	writer := io.MultiWriter(f, h)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	fmt.Printf("[*] Downloaded with SHA256: %s\n", hex.EncodeToString(h.Sum(nil)))
	return nil
}
