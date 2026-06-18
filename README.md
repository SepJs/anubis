# Anubis Security Scanner

> Modular web application security scanner — authorized use only.

```
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
```

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Scanning systems you do not own or have explicit written permission to test is **illegal** and **unethical**. The authors assume no liability for misuse.

---

## Features

| Feature | Details |
|---|---|
| **Scan Levels 1–3** | Progressive intensity from passive recon to deep active scanning |
| **Level 0 Baseline** | Automatic pre-scan baseline (response times, headers, stability) |
| **Worker Pool** | Configurable concurrent module execution |
| **Checkpoint / Resume** | Interrupt at any time, resume with `--resume` |
| **Interactive Prompts** | Asks before continuing on protection detection, time limits, etc. |
| **Multi-format Reports** | HTML, JSON, CSV — combinable with `+` |
| **Batch Mode** | Scan a list of targets from a file |
| **Proxy Support** | Full HTTP/S proxy with optional auth |

---

## Scan Levels

### Level 1 — Light Reconnaissance (5-minute time limit)
- Port scan: top 20 common ports
- SSL/TLS certificate and cipher analysis
- HTTP security header validation
- Sensitive file discovery (`.env`, `.git`, `phpinfo.php`, backups…)

### Level 2 — Active Scanning
All Level 1 modules, plus:
- DNS enumeration and subdomain discovery
- SQL injection detection (error-based)
- Cross-Site Scripting (reflected XSS)
- Default credential testing
- Wider port scan and subdomain list

### Level 3 — Deep Scan
All Level 1–2 modules, plus:
- Full server/CMS/framework fingerprinting
- Wider subdomain enumeration
- Expanded sensitive file discovery
- Deeper port sweep

---

## Modules

| Module | Level | Description |
|---|---|---|
| `PORT_SCAN` | 1 | TCP port scanning with service identification |
| `SSL_CHECK` | 1 | Certificate validity, ciphers, protocol versions |
| `HEADERS` | 1 | Missing/misconfigured security headers |
| `SENSITIVE_FILES` | 1 | Exposed `.env`, `.git`, backups, admin panels |
| `DNS` | 2 | Subdomain brute-force, MX/NS/TXT records, zone transfer check |
| `SQLI` | 2 | SQL injection (error-based, GET parameters) |
| `XSS` | 2 | Reflected XSS detection |
| `BRUTE_FORCE` | 2 | Default credentials, configurable auth strategy |
| `FINGERPRINT` | 3 | Server, OS, CMS, framework detection |

---

## Installation

Requires **Go 1.21+**

```bash
# Clone / download the project
cd anubis

# Download dependencies and build
make deps
make build

# Or install to $GOPATH/bin
make install
```

Cross-compile for all platforms:
```bash
make build-all
# Outputs to: dist/
```

---

## Usage

```bash
# Level 1 — quick passive recon
anubis -t https://example.com -l 1

# Level 2 — active scan, HTML+JSON report
anubis -t https://example.com -l 2 --format html+json -o myreport

# Level 3 — deep scan, more threads
anubis -t https://example.com -l 3 --threads 10 --deep-scan

# Specific modules only
anubis -t https://example.com -l 2 --modules PORT_SCAN,SSL_CHECK,HEADERS

# Disable specific modules
anubis -t https://example.com -l 3 --disable-modules BRUTE_FORCE

# Through Burp Suite proxy
anubis -t https://example.com -l 2 --proxy http://127.0.0.1:8080 --ssl-bypass

# Authenticated scan
anubis -t https://example.com -l 2 -u admin -p password

# Resume after interrupt
anubis --resume

# Batch scan
anubis --batch --batch-file targets.txt -l 1 --format json

# Compare against saved baseline
anubis -t https://example.com -l 1 --baseline anubis_baseline.json

# Verbose output
anubis -t https://example.com -l 2 -v
```

---

## Flags Reference

### Target & Level
| Flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Target URL or IP (required) |
| `-l, --level` | `1` | Scan level: 1, 2, or 3 |

### Output
| Flag | Default | Description |
|---|---|---|
| `--format` | `html+json` | Report format(s): json, html, csv |
| `-o, --output` | auto | Output file base name |
| `--report-level` | `comprehensive` | basic / detailed / comprehensive |

### Connection
| Flag | Default | Description |
|---|---|---|
| `--timeout` | `30` | HTTP timeout (seconds) |
| `--threads` | `5` | Concurrent workers |
| `--rate-limit` | `150` | Delay between requests (ms) |
| `--user-agent` | Anubis UA | Custom User-Agent |
| `--proxy` | — | Proxy URL |
| `--proxy-auth` | — | Proxy credentials (user:pass) |
| `--ssl-bypass` | false | Skip TLS certificate validation |

### Authentication
| Flag | Default | Description |
|---|---|---|
| `-u, --username` | — | Username for auth testing |
| `-p, --password` | — | Password for auth testing |
| `--wordlist` | — | Wordlist for brute-force |
| `--auth-strategy` | `defaults` | none / defaults / bruteforce / combined |

### Behavior
| Flag | Default | Description |
|---|---|---|
| `-v, --verbose` | false | Verbose/debug output |
| `--respect-limits` | false | Respect robots.txt |
| `--deep-scan` | false | More thorough scanning |
| `--baseline` | — | Path to baseline file for comparison |
| `--show-baseline-progress` | true | Show baseline progress bar |

### Batch & Resume
| Flag | Default | Description |
|---|---|---|
| `--batch` | false | Batch mode |
| `--batch-file` | — | File with targets (one per line) |
| `--resume` | false | Resume from checkpoint |

---

## Report Formats

### HTML
Dark-themed interactive report with severity badges, OWASP mappings, remediation steps, and vulnerable/secure code examples.

### JSON
Machine-readable output grouped by severity, type, and endpoint. Includes full metadata and scan duration.

### CSV
Spreadsheet-friendly format with all finding fields. Good for importing into tracking tools.

---

## Project Structure

```
anubis/
├── cmd/anubis/          # CLI entry point (Cobra)
│   ├── main.go
│   ├── root.go          # Flag definitions
│   └── scan.go          # Scan orchestration
├── pkg/
│   ├── baseline/        # Level 0 baseline collection
│   ├── modules/         # Scan modules
│   │   ├── portscan/
│   │   ├── ssl/
│   │   ├── headers/
│   │   ├── sensitive/
│   │   ├── dns/
│   │   ├── sqli/
│   │   ├── xss/
│   │   ├── brute_force/
│   │   └── fingerprint/
│   ├── report/          # JSON/HTML/CSV report generation
│   ├── scanner/         # Engine, types, worker pool
│   ├── state/           # Checkpoint save/load for --resume
│   └── utils/           # HTTP client, logger, prompts
├── Makefile
├── go.mod
└── README.md
```

---

## Adding a New Module

1. Create `pkg/modules/yourmodule/yourmodule.go`
2. Implement the `scanner.Module` interface:
   ```go
   type Module struct{}
   func (m *Module) Name() string             { return "YOUR_MODULE" }
   func (m *Module) Description() string      { return "What it does" }
   func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }
   func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
       // your logic — send findings via the channel
       return nil
   }
   ```
3. Add it to `allModules()` in `cmd/anubis/scan.go`

That's it — the engine picks it up automatically.

---

*Inner Void Studio — Built for authorized security testing*
