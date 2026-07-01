# Anubis v2.0

> Elite modular security scanner — AI-driven heuristics, polymorphic evasion, zero-CGO architecture.

```
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
```

**Version:** 2.0.0 | **Author:** Vladimir Unknown | **License:** MIT

---

## Features


╔══════════════════╤══════════════════════════════════════════════════════════════════════════════════════════╗
║     Category     │                         Capabilities                                                     ║
╠══════════════════╪══════════════════════════════════════════════════════════════════════════════════════════╣
║ Engine           │ Worker-pool concurrency, atomic state, context cancellation, zero memory leaks           ║
║ Evasion          │ Polymorphic jitter, randomized delays, packet padding, DPI bypass                        ║
║ Proxy            │ SOCKS5/HTTP/HTTPS rotation, health checking, automatic failover                          ║
║ Stealth          │ Ghost mode, browser fingerprint spoofing, cURL/Wget mimicry                              ║
║ Adaptive         │ AI-driven latency analysis, trend-based speed adjustment, anti-rate-limit                ║
║ Scanner          │ 9 modules + subdomain discovery, CVSS scoring, heuristic likelihood analysis             ║
║ Reporting        │ HTML (risk meter, CVSS vectors), JSON, CSV + encrypted SQLite history                    ║
║ API              │ gRPC remote control with TLS + token auth                                                ║
║ WAF Bypass       │ Double URL encoding, nested Base64, Unicode escape, comment injection                    ║
║ Anti-Sandbox     │ Honeypot detection, sandbox environment identification                                   ║
║ Security         │ Input sanitization, panic recovery → crash.log, stripped+PIE binary                      ║
║ Platform         │ Linux/Windows/macOS, zero CGO dependencies, fully static binaries                        ║
╚══════════════════╧══════════════════════════════════════════════════════════════════════════════════════════╝

---

## Quick Install

### Linux / macOS
```bash
git clone https://github.com/SepJs/anubis
cd anubis
make deps build
sudo cp anubis /usr/local/bin/
```

### macOS (Homebrew)
```bash
# Coming soon to a tap near you
brew install SepJs/anubis/anubis
```

### Windows (PowerShell)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SepJs/anubis/main/install.ps1'))
```

---

## Usage

### Basic Scanning
```bash
# Passive recon (stealth)
anubis -t https://example.com -l 1

# Active scanning with ghost mode
anubis -t https://example.com -l 2 --ghost --strategy polymorphic

# Deep aggressive scan
anubis -t https://example.com -l 3 --threads 20 --deep-scan
```

### Evasion & Stealth
```bash
# Ghost mode — zero stdout findings, minimal requests
anubis -t https://example.com -l 2 --ghost

# Proxy rotation (SOCKS5)
anubis -t https://example.com --proxy socks5://127.0.0.1:9050

# Polymorphic delay — rotates between 4 delay patterns
anubis -t https://example.com -l 2 --strategy polymorphic

# Randomized jitter with custom variance
anubis -t https://example.com -l 2 --strategy randomized

# Full stealth profile from config
anubis -c templates/default.yaml -t https://example.com
```

### Configuration
```bash
# Use YAML config with profiles
anubis -c myconfig.yaml -t https://example.com -l 2

# Example config profiles:
#   stealth   — 3 threads, 500ms delay, ghost mode, polymorphic
#   aggressive — 50 threads, 10ms delay, fixed strategy
#   default   — 10 threads, 150ms delay, jitter strategy
```

### Advanced Features
```bash
# Profile mode (CPU/mem/trace)
anubis -t https://example.com -l 1 --profile

# Resume interrupted scan
anubis --resume

# Batch scan targets
anubis --batch --batch-file targets.txt -l 1

# Update to latest version
anubis --update

# Generate documentation
anubis --gendoc
```

---

## Architecture

```
╭──────────────────────────────────────────────────────────────────────────────────╮
│                              🔥  ANUBIS  🔥                                      │
├──────────────┬───────────────────────────────────────────────────────────────────┤
│ ENGINE       │ Worker-pool concurrency │ Atomic state │ Context cancellation     │
│              │ Zero memory leaks                                                 │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ EVASION      │ Polymorphic jitter │ Randomized delays │ Packet padding           │
│              │ DPI bypass                                                        │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ PROXY        │ SOCKS5/HTTP/HTTPS rotation │ Health checking │ Auto failover      │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ STEALTH      │ Ghost mode │ Browser fingerprint spoofing │ cURL/Wget mimicry     │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ ADAPTIVE     │ AI-driven latency analysis │ Trend-based speed adjustment         │
│              │ Anti-rate-limit                                                   │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ SCANNER      │ 9 modules + subdomain discovery │ CVSS scoring                    │
│              │ Heuristic likelihood analysis                                     │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ REPORTING    │ HTML (risk meter, CVSS vectors) │ JSON │ CSV                      │
│              │ Encrypted SQLite history                                          │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ API          │ gRPC remote control with TLS + token auth                         │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ WAF BYPASS   │ Double URL encoding │ Nested Base64 │ Unicode escape              │
│              │ Comment injection                                                 │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ ANTI-SANDBOX │ Honeypot detection │ Sandbox environment identification           │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ SECURITY     │ Input sanitization │ Panic recovery → crash.log                   │
│              │ stripped+PIE binary                                               │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ PLATFORM     │ Linux/Windows/macOS │ Zero CGO dependencies                       │
│              │ Fully static binaries                                             │
├──────────────┴───────────────────────────────────────────────────────────────────┤
│                    ⚡ Zero CGO │ 🌍 Cross-Platform │ 📦 Static                    │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

---

## Modules

╭─────────────────────────────────────────────────────────────────────────────────╮
│                          🔍  SCAN MODULES  🔍                                   │
├──────────────┬─────────┬────────────────────────────────────────────────────────┤
│ MODULE       │ LEVEL   │ DESCRIPTION                                            │
├──────────────┼─────────┼────────────────────────────────────────────────────────┤
│ PORT_SCAN    │  ⚪ 1   │ TCP port scanning with service detection               │
│ SSL_CHECK    │  ⚪ 1   │ TLS/SSL certificate analysis                           │
│ HEADERS      │  ⚪ 1   │ HTTP security headers audit                            │
│ SENSITIVE    │  ⚪ 1   │ Sensitive file/directory discovery                     │
│ _FILES       │         │                                                        │
├──────────────┼─────────┼────────────────────────────────────────────────────────┤
│ DNS          │  🟡 2   │ DNS enumeration and subdomain discovery                │
│ SQLI         │  🟡 2   │ SQL injection detection                                │
│ XSS          │  🟡 2   │ Cross-site scripting detection                         │
│ BRUTE_FORCE  │  🟡 2   │ Default credential testing                             │
│ DISCOVERY    │  🟡 2   │ Passive + brute-force subdomain discovery              │
├──────────────┼─────────┼────────────────────────────────────────────────────────┤
│ FINGERPRINT  │  🔴 3   │ Web stack fingerprinting                               │
├──────────────┴─────────┴────────────────────────────────────────────────────────┤
│  9 modules  │  ⚪ L1: Recon  │  🟡 L2: Attack  │  🔴 L3: Deep                   │
╰─────────────────────────────────────────────────────────────────────────────────╯

---

## Packaging

### Homebrew (macOS/Linux)
```bash
# Local tap
brew install --HEAD ./anubis.rb

# Future: official tap
brew tap SepJs/anubis
brew install anubis
```

### PowerShell Gallery (Windows)
```powershell
# One-liner install
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SepJs/anubis/main/install.ps1'))
```

### Docker
```dockerfile
FROM golang:1.21-alpine AS build
RUN apk add --no-cache git
COPY . /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /anubis ./cmd/anubis

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /anubis /usr/local/bin/anubis
ENTRYPOINT ["anubis"]
```

---

## Disclaimer

This tool is for **authorized security testing only**. Scanning systems you don't own or have written permission to test is illegal. The author assumes no liability for misuse. 
