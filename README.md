# Anubis

> Modular web application security scanner — authorized use only.

```
  █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
 ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
 ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
 ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
 ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
 ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
```

**Author:** Unknown XRG  
**GitHub:** [SepJs/anubis](https://github.com/SepJs/anubis)

---

## Install

Requires **Go 1.21+**

```bash
git clone https://github.com/SepJs/anubis
cd anubis
make deps
make build
sudo cp anubis /usr/local/bin/
```

> Version shown in `--version` is stamped automatically from the latest Git
> tag at build time. If you clone without any tags, it shows `dev`.

---

## Usage

```bash
# Level 1 — passive reconnaissance (5-minute limit)
anubis -t https://example.com -l 1

# Level 2 — active scanning
anubis -t https://example.com -l 2 -v

# Level 3 — deep scan, all modules
anubis -t https://example.com -l 3 --format html+json

# Through Burp proxy
anubis -t https://example.com -l 2 --proxy http://127.0.0.1:8080 --ssl-bypass

# Batch scan (one target per line)
anubis --batch --batch-file targets.txt -l 1

# Resume interrupted scan
anubis --resume

# Check for / install update
anubis --check-update
anubis --update
```

Reports are saved automatically to the `reports/` directory.

---

## Scan Levels

| Level | Modules | Notes |
|-------|---------|-------|
| **1** | PORT_SCAN, SSL_CHECK, HEADERS, SENSITIVE_FILES | Passive-ish, 5-min time limit |
| **2** | + DNS, SQLI, XSS, BRUTE_FORCE | Active scanning |
| **3** | + FINGERPRINT | Full deep scan |

---

## Flags

```
Target:
  -t, --target STRING      Target URL (required)
  -l, --level INT          Scan level 1-3 (default: 1)

Output:
  --format STRING          json, html, csv — combine with + (default: html+json)
  -o, --output STRING      Output file name (default: auto in reports/)
  --report-level STRING    basic | detailed | comprehensive (default: comprehensive)

Connection:
  --timeout INT            HTTP timeout in seconds (default: 30)
  --threads INT            Concurrent workers (default: 5)
  --rate-limit INT         Delay between requests in ms (default: 150)
  --strategy STRING        fixed | exponential | linear | jitter (default: jitter)
  --max-delay INT          Maximum delay cap in ms (default: 60000)
  --adaptive-delay         Auto-adjust delay on 429/503 responses
  --proxy URL              Proxy URL
  --ssl-bypass             Skip TLS certificate validation

Auth:
  -u, --username STRING
  -p, --password STRING
  --auth-strategy STRING   none | defaults | bruteforce | combined (default: defaults)

Modules:
  --modules STRING         Run only these modules (comma-separated)
  --disable-modules STRING Skip these modules

Behavior:
  -v, --verbose            Debug output
  --respect-limits         Respect robots.txt
  --deep-scan              More thorough per-module scanning

Update:
  --check-update           Check GitHub for newer release (no download)
  --update                 Download and install latest release

Other:
  --resume                 Resume from last checkpoint
  --batch --batch-file F   Scan multiple targets from file
  --version                Print version and exit
```

---

## Reports

All reports go to `reports/` — created automatically on first scan.

```
reports/
├── anubis_example_com_20260618_143022.html   ← full HTML report
├── anubis_example_com_20260618_143022.json   ← machine-readable
└── anubis_baseline.json                      ← baseline for comparison
```

To compare against a saved baseline:
```bash
anubis -t https://example.com -l 1 --baseline reports/anubis_baseline.json
```

---

## Auto-Update

Every scan run does a background update check against GitHub releases. If a
newer version is available, you'll see a one-line notice after scan startup.

To actually update:
```bash
anubis --update   # confirms before replacing the binary; backup saved as .anubis-previous
```

Version is synced with Git release tags. To release a new version:
```bash
make release TAG=v1.2.0   # requires gh CLI installed
```

This tags, pushes, cross-compiles, and creates the GitHub release in one step.

---

## Adding a Module

```go
// pkg/modules/mymodule/mymodule.go
package mymodule

import "github.com/SepJs/anubis/pkg/scanner"

type Module struct{}
func New() *Module { return &Module{} }
func (m *Module) Name() string             { return "MY_MODULE" }
func (m *Module) Description() string      { return "Does something useful" }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level2 }
func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding) error {
    findings <- scanner.Finding{ Title: "Found X", Severity: scanner.SeverityHigh, /* ... */ }
    return nil
}
```

Then add `mymodule.New()` to `allModules()` in `cmd/anubis/scan.go`.

---

## Disclaimer

This tool is for **authorized security testing only**.  
Scanning systems you don't own or have written permission to test is illegal.
