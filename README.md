# Anubis v2.5.2

> Elite modular security scanner — AI-driven heuristics, polymorphic evasion, zero-CGO architecture.

```
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██╗██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
```

**Version:** 2.5.2 | **Author:** Vladimir Unknown | **License:** MIT

---

## What's New in v2.5.2

- **3 new scan modules** — LFI, SSTI, Open Redirect
- **Built-in web crawler** (`--crawl`) — feeds real endpoints to injection modules
- **Nuclei-style YAML template engine** (`--templates`) — custom checks without Go code
- **Rewritten SQLi detection** — error-based + boolean blind + time-based blind with baseline comparison (dramatically fewer false positives)
- **Smarter XSS detection** — unescaped-reflection verification with context analysis
- **External wordlists** for sensitive-file discovery via `--wordlist`
- **Certificate Transparency** subdomain discovery via crt.sh (`--external-api`)
- **One-line installers** for Linux, macOS, and Windows with automatic OS detection

---

## Features

| Category         | Capabilities                                                                   |
| ---------------- | ------------------------------------------------------------------------------ |
| **Engine**       | Worker-pool concurrency, atomic state, context cancellation, zero memory leaks |
| **Evasion**      | Polymorphic jitter, randomized delays, packet padding, DPI bypass              |
| **Proxy**        | SOCKS5 / HTTP / HTTPS rotation, health checking, automatic failover            |
| **Stealth**      | Ghost mode, browser fingerprint spoofing, cURL / Wget mimicry                  |
| **Adaptive**     | AI-driven latency analysis, trend-based speed adjustment, anti-rate-limit      |
| **Crawler**      | Same-host link & GET-form discovery, depth/page limits, feeds injection modules |
| **Templates**    | Nuclei-style YAML custom checks — matchers, payloads, no Go code required      |
| **Scanner**      | 12 modules + subdomain discovery, CVSS scoring, heuristic likelihood analysis  |
| **Detection**    | Error-based, boolean-blind, and time-based SQLi; reflected-XSS context analysis|
| **Reporting**    | HTML (risk meter, CVSS vectors), JSON, CSV + encrypted SQLite history          |
| **API**          | gRPC remote control with TLS + token authentication                            |
| **WAF Bypass**   | Double URL encoding, nested Base64, Unicode escape, comment injection          |
| **Anti-Sandbox** | Honeypot detection, sandbox environment identification                         |
| **Security**     | Input sanitization, panic recovery to user cache dir, stripped + PIE binary    |
| **Platform**     | Linux / Windows / macOS, zero CGO dependencies, fully static binaries          |

---

## Quick Install

### One-liner (recommended)

**Linux / macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SepJs/anubis/main/install.ps1'))
```

The installer detects your OS and architecture automatically, then either
downloads a prebuilt release binary or falls back to building from source
with Go.

### From source (any platform)
```bash
git clone https://github.com/SepJs/anubis
cd anubis
make deps build
sudo cp anubis /usr/local/bin/
```

### macOS (Homebrew)
```bash
brew install SepJs/anubis/anubis
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

### Crawler
```bash
# Discover endpoints first, then test them with injection modules
anubis -t https://example.com -l 2 --crawl --crawl-depth 2 --crawl-max-pages 50
```

The crawler extracts same-host links with query strings and GET forms
(input names become testable parameters) and feeds everything to the
injection modules — dramatically increasing coverage on multi-page apps.

### Evasion & Stealth
```bash
# Ghost mode — minimal requests, time-based checks disabled
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

### Custom YAML Templates
```bash
# Run your own checks (Nuclei-style) from a directory of YAML files
anubis -t https://example.com -l 2 --templates ./templates/custom
```

Example template:
```yaml
id: admin-panel-detect
name: "Admin Panel Detection"
severity: low
level: 1
endpoint: /admin
method: GET
condition: and
matchers:
  - type: status
    value: "200"
  - type: contains
    value: "admin"
remediation: "Restrict /admin to authenticated users."
```

Matcher types: `contains`, `regex`, `status`, `header`, `words` — combined
with `condition: and|or`, optional inline or file-based payloads, custom
placeholder syntax, CVSS / OWASP mapping, and remediation text.

### Configuration
```bash
# Use YAML config with profiles
anubis -c myconfig.yaml -t https://example.com -l 2

# Example config profiles:
#   stealth    — 3 threads, 500ms delay, ghost mode, polymorphic
#   aggressive — 50 threads, 10ms delay, fixed strategy
#   default    — 10 threads, 150ms delay, jitter strategy
```

### Advanced Features
```bash
# Profile mode (CPU/mem/trace)
anubis -t https://example.com -l 1 --profile

# Resume interrupted scan
anubis --resume

# Batch scan targets
anubis --batch --batch-file targets.txt -l 1

# External wordlist (feeds sensitive-file discovery AND brute-force)
anubis -t https://example.com -l 1 --wordlist ~/seclists/Discovery/Web-Content/common.txt

# Certificate Transparency subdomain discovery (crt.sh)
anubis -t example.com -l 2 --external-api

# Update to latest version
anubis --update

# Generate documentation
anubis --gendoc
```

---

## Architecture

```text
╭──────────────────────────────────────────────────────────────────────────────────╮
│                                    ANUBIS                                        │
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
│ CRAWLER      │ Same-host link extraction │ GET-form parsing │ depth/page limits   │
│              │ Feeds discovered endpoints to injection modules                   │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ SCANNER      │ 13 modules + subdomain discovery │ CVSS scoring                   │
│              │ Heuristic likelihood analysis                                     │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ TEMPLATES    │ YAML custom checks │ Nuclei-style matchers │ No Go code needed    │
│              │ contains / regex / status / header / words matchers               │
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
│ SECURITY     │ Input sanitization │ Panic recovery → user cache dir              │
│              │ Stripped + PIE binary                                             │
├──────────────┼───────────────────────────────────────────────────────────────────┤
│ PLATFORM     │ Linux / Windows / macOS │ Zero CGO dependencies                   │
│              │ Fully static binaries                                             │
├──────────────┴───────────────────────────────────────────────────────────────────┤
│                   Zero CGO  │  Cross-Platform   │  Static                        │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

---

## Scan Modules

| Module              | Level | Description                                          |
| ------------------- | ----- | ---------------------------------------------------- |
| **PORT_SCAN**       | ⚪ L1 | TCP port scanning with service detection             |
| **SSL_CHECK**       | ⚪ L1 | TLS/SSL certificate analysis                         |
| **HEADERS**         | ⚪ L1 | HTTP security headers audit                          |
| **SENSITIVE_FILES** | ⚪ L1 | Sensitive file discovery (supports `--wordlist`)     |
| **DNS**             | 🟡 L2 | DNS enumeration, brute-force + CT-log subdomain discovery |
| **SQLI**            | 🟡 L2 | SQL injection — error, boolean-blind, time-blind     |
| **XSS**             | 🟡 L2 | Reflected XSS with context analysis                  |
| **BRUTE_FORCE**     | 🟡 L2 | Default credential testing                           |
| **FINGERPRINT**     | 🔴 L3 | Web stack fingerprinting                             |
| **LFI**             | 🟡 L2 | Path traversal / local file inclusion                |
| **SSTI**            | 🟡 L2 | Server-side template injection                       |
| **OPENREDIRECT**    | 🟡 L2 | Unvalidated redirect detection (canary host)         |
| **TEMPLATE**        | L- dep. | Your YAML-defined custom checks                    |

**Total built-in modules:** 12

### Levels Overview

* ⚪ **L1 – Recon**: Basic reconnaissance and passive analysis
* 🟡 **L2 – Attack**: Active vulnerability testing
* 🔴 **L3 – Deep**: Advanced fingerprinting and deep inspection

---

## Custom Templates

Create `templates/custom/my-check.yaml`:

```yaml
id: exposed-git-config
name: "Exposed .git/config"
description: "Checks whether the .git/config file is publicly readable"
severity: critical
level: 1
endpoint: /.git/config
method: GET
condition: and
matchers:
  - type: status
    value: "200"
  - type: contains
    value: "[core]"
cvss: 7.5
owasp: "A05:2021 – Security Misconfiguration"
remediation: "Block access to .git directories at the web server level."
```

Supported matcher types: `contains` · `regex` · `status` · `header` · `words`

Combine matchers with `condition: and | or`, attach inline or file-based
payload lists, and use `{{payload}}` substitution anywhere in params or body.

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

### One-liner installers
```bash
# Linux / macOS
curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
```
```powershell
# Windows
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
