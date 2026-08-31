# ═══════════════════════════════════════════════════════
#  Anubis installer — Windows (PowerShell)
#  Usage:  iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SepJs/anubis/main/install.ps1'))
# ═══════════════════════════════════════════════════════
$ErrorActionPreference = "Stop"

$Repo = "SepJs/anubis"

function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Die($msg)         { Write-Host "[X] $msg" -ForegroundColor Red; exit 1 }

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    "x86"   { "386"   }
    default { Die "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

Write-Info "Detected: windows/$Arch"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\anubis"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Try-ReleaseInstall {
    try {
        Write-Info "Fetching latest release info..."
        $headers = @{ "User-Agent" = "anubis-installer" }
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -TimeoutSec 30
        $tag = $rel.tag_name
        Write-Info "Latest release: $tag"

        $assetName = "anubis_${tag.TrimStart('v')}_windows_${Arch}.zip"
        $asset = $rel.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
        if (-not $asset) {
            Write-Warn2 "Asset $assetName not found in release $tag"
            return $false
        }

        $zipPath = Join-Path $env:TEMP $assetName
        Write-Info "Downloading $($asset.browser_download_url)..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -TimeoutSec 120

        Write-Info "Extracting..."
        Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Warn2 "Release install failed: $_"
        return $false
    }
}

function Try-SourceInstall {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warn2 "Go not found"
        return $false
    }
    Write-Info "Building from source..."
    try {
        $tmp = Join-Path $env:TEMP "anubis-build-$(Get-Random)"
        git clone --depth 1 "https://github.com/$Repo.git" $tmp 2>$null
        if (-not (Test-Path "$tmp\cmd")) { return $false }

        Push-Location $tmp
        $env:CGO_ENABLED = "0"
        go build -trimpath -ldflags "-s -w" -o "$InstallDir\anubis.exe" .\cmd\anubis
        Pop-Location
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        return (Test-Path "$InstallDir\anubis.exe")
    } catch {
        Write-Warn2 "Source install failed: $_"
        return $false
    }
}

function Add-ToUserPath($dir) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
        $env:Path = "$env:Path;$dir"
        Write-Ok "Added $dir to user PATH"
    }
}

$installed = $false
if (Try-ReleaseInstall) {
    Write-Ok "Installed from GitHub release"
    $installed = $true
} elseif (Try-SourceInstall) {
    Write-Ok "Built and installed from source"
    $installed = $true
} else {
    Die "Could not install Anubis — install Go from https://golang.org/dl and retry"
}

Add-ToUserPath $InstallDir

$exe = Join-Path $InstallDir "anubis.exe"
if (Test-Path $exe) {
    Write-Ok "anubis.exe ready at $exe"
    Write-Host ""
    Write-Host "  Open a NEW terminal and try:" -ForegroundColor Cyan
    Write-Host "    anubis -t https://example.com -l 1" -ForegroundColor Yellow
} else {
    Die "anubis.exe not found after install"
}
