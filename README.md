# Anubis v2.6.0 — Enterprise-Grade CLI Security Scanner & Vulnerability Audit Engine

```
   █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
  ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
  ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
  ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
  ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
```

[![Release](https://img.shields.io/badge/release-v2.6.0-red.svg?style=flat-square)](https://github.com/SepJs/anubis/releases)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20Distros%20(x86__64%20%7C%20arm64)-orange.svg?style=flat-square)](#quick-download--install)
[![Architecture](https://img.shields.io/badge/architecture-Zero--CGO%20Static-green.svg?style=flat-square)](#architecture)

**Anubis** is a fast, zero-dependency, static vulnerability audit engine and network assessment CLI designed specifically for Linux environments (Ubuntu, Debian, Kali Linux, Arch, Fedora, Alpine). Built as a standalone portable binary with zero external runtime dependencies.

---

## ⚡ What's New in v2.6.0

- 🎯 **Standardized CLI Manual (`--help`)**: Organized into clear, categorized functional groups matching industry-standard Linux utilities.
- 🕷️ **End-to-End Crawler Pipeline**: The high-speed recursive crawler (`--crawl`) is directly hooked into the active audit phase to discover internal endpoints, links, and forms.
- 🤫 **Native Unix Pipe Integration (`-s`, `--silent`)**: Strips out banners and interactive logs for seamless piping with standard Unix utilities (`grep`, `jq`, `awk`).
- 🛡️ **Polymorphic Anti-WAF & Jitter Timing**: Dynamic signature morphing and health-based adaptive throttling to evade modern cloud WAFs and rate limiters.
- 📦 **Instant Zero-Setup Linux Distribution**: Standalone pre-compiled Linux binaries (`amd64` / `arm64`) with no runtime or language installation required.

---

## 🚀 Key Capabilities

| Domain | Highlights |
| :--- | :--- |
| **Audit Engine** | Worker-pool concurrency, atomic state persistence, graceful signal trapping (`SIGINT`/`SIGTERM`), zero memory leaks. |
| **Vulnerability Modules** | SQL Injection, XSS, LFI, SSTI, Open Redirect, Sensitive Data/Env Leaks, Security Headers, Port Scanner, TLS/SSL Ciphers, DNS Enumeration, Tech Fingerprinting. |
| **Web Crawler** | Same-origin link & form discovery, depth recursion control (`--crawl-depth`), page count limits (`--crawl-max-pages`), robots.txt compliance. |
| **YAML Templates** | Nuclei-style custom vulnerability check templates (`--templates <dir>`) with matchers and condition logic. |
| **Evasion & Stealth** | Ghost mode (`--ghost`), dynamic User-Agent rotation, polymorphic jitter, delay backoff strategies (`jitter`, `polymorphic`, `exponential`, `linear`, `fixed`). |
| **Network & Proxies** | Multi-hop SOCKS5/HTTP/HTTPS proxy rotation, Tor routing (`socks5://127.0.0.1:9050`), custom CA bundles, SSL verification bypass. |
| **Reporting** | Standalone executive HTML reports, JSON for automation, CSV for tabular audit analysis, OWASP Top 10 / CIS framework mappings. |
| **Architecture** | 100% Go, Zero CGO, static binaries with stripped symbol tables (`-ldflags="-s -w"`). |

---

## 📥 Quick Download & Install

### Option A: One-Line Automatic Downloader (Recommended)

Downloads the pre-compiled standalone binary directly to `/usr/local/bin/anubis`:

```bash
curl -sSL https://raw.githubusercontent.com/SepJs/anubis/main/install.sh | bash
```

### Option B: Direct Binary Download (Zero Setup)

Simply download the executable for your Linux architecture, make it executable, and run:

**For Linux x86_64 (amd64 / Ubuntu / Debian / Kali / Arch):**
```bash
curl -sSL https://github.com/SepJs/anubis/releases/latest/download/anubis_2.6.0_linux_amd64 -o anubis
chmod +x anubis
sudo mv anubis /usr/local/bin/
```

**For Linux ARM64 (aarch64 / Raspberry Pi / Cloud ARM):**
```bash
curl -sSL https://github.com/SepJs/anubis/releases/latest/download/anubis_2.6.0_linux_arm64 -o anubis
chmod +x anubis
sudo mv anubis /usr/local/bin/
```

Verify the installation:
```bash
anubis --version
```

### Option C: Compile from Source (Optional)

```bash
git clone https://github.com/SepJs/anubis.git
cd anubis
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o anubis ./cmd/anubis
sudo mv anubis /usr/local/bin/
```

---

## 💻 Usage & CLI Reference

```text
USAGE:
  anubis -t <target> [flags]

TARGET SPECIFICATION:
  -t, --target <url/ip>        Target URL or IP address (e.g. https://example.com)
  -b, --batch-file <path>      Scan multiple targets from text file (one per line)
      --batch                  Enable batch target execution mode
      --resume                 Resume interrupted scan from checkpoint (.anubis.state)

SCAN LEVEL & AUDIT MODES:
  -l, --level <1|2|3>          Audit depth: 1=Passive Recon, 2=Active Audit, 3=Deep Scan (default: 1)
  -m, --modules <list>         Comma-separated list of modules to execute
      --disable-modules <list> Comma-separated list of modules to skip
      --quick-vuln             Stop each module immediately upon first verified vulnerability
      --deep-scan              Enable exhaustive payload fuzzing (slower, maximum depth)
      --module-priority <mode> Module order: severity, speed, comprehensive (default: severity)

CRAWLER & TARGET DISCOVERY:
      --crawl                  Crawl target to discover internal endpoints, links & forms
      --crawl-depth <int>      Crawler link recursion depth limit (default: 2)
      --crawl-max-pages <int>  Crawler max total unique pages to explore (default: 30)
      --respect-limits         Respect target robots.txt rules and crawl delay directives

CUSTOM CHECK TEMPLATES:
      --templates <dir>        Directory of YAML custom vulnerability check templates

EVASION & ANTI-WAF:
      --ghost                  Ghost mode: randomize signatures and minimize detection footprint
      --strategy <name>        Delay pattern: jitter, polymorphic, exponential, linear, fixed (default: jitter)
      --max-delay <ms>         Maximum evasion delay threshold in milliseconds (default: 60000)
      --adaptive-delay         Dynamically adjust request throttling based on server health (default: true)
      --rate-limit <ms>        Base delay between requests in milliseconds (default: 150)

AUTHENTICATION & INPUTS:
  -u, --username <user>        Username for HTTP Basic or Form authentication
  -p, --password <pass>        Password for authenticated audits
  -w, --wordlist <path>        Custom dictionary file for path discovery and bruteforce
      --payload-file <path>    Custom injection payload dictionary file
      --auth-strategy <mode>   Auth strategy: none, defaults, bruteforce, combined (default: defaults)

NETWORK & PROXY:
      --proxy <url>            HTTP/HTTPS/SOCKS5 proxy URL (e.g. socks5://127.0.0.1:9050)
      --proxy-auth <user:pass> Proxy authentication credentials in user:password format
      --timeout <sec>          HTTP request and connection timeout in seconds (default: 30)
      --threads <int>          Number of concurrent worker goroutines (default: 10)
      --ssl-bypass             Bypass SSL/TLS certificate validation (insecure mode)
      --ca-cert <path>         Path to custom CA certificate authority bundle
      --user-agent <str>       Custom User-Agent header (defaults to polymorphic UA pool)
      --protocols <list>       Protocols to audit: http, https (default: http,https)

OUTPUT & REPORTING:
  -o, --output <file>          Base filename or directory for output reports
  -f, --format <format>        Report formats: html, json, csv (combine with +, default: html+json)
      --report-level <lvl>     Reporting detail level: basic, detailed, comprehensive (default: comprehensive)
      --baseline <file>        Compare current scan findings against a previous baseline file
      --framework-map          Map discovered findings to OWASP Top 10 and CIS benchmarks
      --framework-examples <m> Include mitigation code examples: owasp, cis, both

GENERAL & SYSTEM:
  -v, --verbose                Enable verbose real-time debugging output
  -s, --silent                 Silent mode: suppress banner & non-finding logs for Unix pipes
  -c, --config <file>          Load scan configuration options from YAML file
      --profile                Enable CPU, memory, and runtime execution profiling
      --check-update           Check GitHub for newer releases without downloading
      --update                 Download and install the latest Anubis release
      --version                Print version, architecture, and build information
  -h, --help                   Display this help manual
```

---

## 🛠️ Practical Examples

### 1. Stealth Passive Reconnaissance
Run a passive footprinting audit with TLS/SSL verification, security headers analysis, and DNS discovery:
```bash
anubis -t https://example.com -l 1
```

### 2. Active Vulnerability Audit with Crawler & Anti-WAF
Crawl target endpoints and run injection audits using polymorphic evasion:
```bash
anubis -t https://example.com -l 2 --crawl --ghost --strategy polymorphic
```

### 3. Deep Fuzzing with Custom YAML Templates Routed via Tor
Execute exhaustive payload fuzzing through a SOCKS5 Tor proxy:
```bash
anubis -t https://example.com -l 3 --templates templates/custom --proxy socks5://127.0.0.1:9050
```

### 4. Headless CI/CD Unix Pipeline (Silent Mode)
Extract critical findings in JSON format directly in your pipeline:
```bash
anubis -t https://example.com -l 2 -s -f json -o report | jq '.findings[] | select(.severity=="CRITICAL")'
```

### 5. Multi-Target Batch Audit
Scan an entire IP range or URL list and generate both HTML and JSON reports:
```bash
anubis --batch -b targets.txt -l 2 -o client_audit -f html+json
```

---

## 🛡️ Legal & Ethical Disclaimer

> [!WARNING]
> **Anubis is designed strictly for authorized penetration testing, vulnerability assessments, and educational security research.**
> 
> Running unauthorized scans against targets without prior explicit written consent is illegal and violates computer fraud laws. The developers and contributors assume no liability and are not responsible for any misuse, damage, or legal consequences caused by this software.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
