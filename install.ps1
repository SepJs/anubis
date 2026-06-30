<#
.SYNOPSIS
    Anubis Security Scanner — Windows PowerShell Installer
.DESCRIPTION
    Downloads and installs the latest Anubis release for Windows.
    Supports automatic PATH installation and verification.
.PARAMETER Version
    Specific version to install (default: latest)
.PARAMETER InstallDir
    Installation directory (default: $HOME\anubis)
.PARAMETER AddToPath
    Add Anubis to system PATH (default: true)
.PARAMETER Force
    Overwrite existing installation without prompting
.EXAMPLE
    .\install.ps1
    .\install.ps1 -Version v2.0.0
    .\install.ps1 -InstallDir C:\tools\anubis -AddToPath $true
#>

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$HOME\anubis",
    [bool]$AddToPath = $true,
    [switch]$Force
)

$RepoUrl = "https://api.github.com/repos/SepJs/anubis/releases/latest"
$DownloadBase = "https://github.com/SepJs/anubis/releases/download"

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       Anubis Security Scanner           ║" -ForegroundColor Cyan
Write-Host "║         Windows Installation            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Detect architecture
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$BinaryName = "anubis-windows-$Arch.exe"

# Determine version
if ($Version -eq "latest") {
    Write-Host "[*] Fetching latest release info..." -ForegroundColor Yellow
    try {
        $Release = Invoke-RestMethod -Uri $RepoUrl -UserAgent "anubis-installer"
        $Version = $Release.tag_name
        $Asset = $Release.assets | Where-Object { $_.name -eq $BinaryName }
        if (-not $Asset) {
            Write-Error "[-] No asset found for $BinaryName in release $Version"
            exit 1
        }
        $DownloadUrl = $Asset.browser_download_url
        $ChecksumUrl = $DownloadUrl + ".sha256"
    } catch {
        Write-Error "[-] Failed to fetch release info: $_"
        exit 1
    }
} else {
    $DownloadUrl = "$DownloadBase/$Version/$BinaryName"
    $ChecksumUrl = "$DownloadBase/$Version/$BinaryName.sha256"
}

Write-Host "[*] Version: $Version" -ForegroundColor Green
Write-Host "[*] Architecture: $Arch" -ForegroundColor Green
Write-Host "[*] Binary: $BinaryName" -ForegroundColor Green

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[+] Created directory: $InstallDir" -ForegroundColor Green
}

$OutputPath = Join-Path $InstallDir "anubis.exe"

# Download binary
Write-Host "[*] Downloading $BinaryName ..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutputPath -UserAgent "anubis-installer"
    Write-Host "[+] Downloaded to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Error "[-] Download failed: $_"
    exit 1
}

# Verify checksum
Write-Host "[*] Verifying checksum..." -ForegroundColor Yellow
try {
    $ChecksumContent = Invoke-RestMethod -Uri $ChecksumUrl -UserAgent "anubis-installer"
    $ExpectedHash = $ChecksumContent.Split(' ')[0]
    $ActualHash = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash.ToLower()
    if ($ActualHash -eq $ExpectedHash) {
        Write-Host "[+] Checksum verified: $ExpectedHash" -ForegroundColor Green
    } else {
        Write-Warning "[-] Checksum mismatch!"
        Write-Warning "    Expected: $ExpectedHash"
        Write-Warning "    Actual:   $ActualHash"
        if (-not $Force) {
            $confirm = Read-Host "[?] Continue with installation anyway? (y/N)"
            if ($confirm -ne 'y') { exit 1 }
        }
    }
} catch {
    Write-Warning "[-] Checksum verification skipped: $_"
}

# Set execution bit (Windows equivalent — just mark as executable, though it's always executable)
Write-Host "[+] Binary installed at: $OutputPath" -ForegroundColor Green

# Add to PATH
if ($AddToPath) {
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($CurrentPath -notlike "*$InstallDir*") {
        $NewPath = "$CurrentPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
        Write-Host "[+] Added $InstallDir to user PATH" -ForegroundColor Green
        Write-Host "[!] Restart your terminal for PATH changes to take effect" -ForegroundColor Yellow
    } else {
        Write-Host "[*] $InstallDir already in PATH" -ForegroundColor Cyan
    }
}

# Test installation
Write-Host ""
Write-Host "[*] Testing installation..." -ForegroundColor Yellow
try {
    $VersionOutput = & "$OutputPath" --version 2>&1
    Write-Host "[+] $VersionOutput" -ForegroundColor Green
} catch {
    Write-Warning "[-] Could not verify installation: $_"
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        Installation Complete!            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:"
Write-Host "  anubis -t https://example.com -l 1"
Write-Host "  anubis -t https://example.com -l 2 --ghost"
Write-Host ""
Write-Host "Documentation: https://github.com/SepJs/anubis" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Authorized use only." -ForegroundColor Yellow
Write-Host "Scanning systems without permission is illegal." -ForegroundColor Yellow
