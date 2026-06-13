# Anubis — Advanced Modular Web Security & Auditing Framework

█████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝


[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-black?style=flat-square)](https://github.com/unknown-xrg/anubis)
[![Security Auditing](https://img.shields.io/badge/Purpose-Authorized%20Penetration%20Testing-red?style=flat-square)](#legal-disclaimer)

Anubis is a high-performance, concurrent web application security framework designed for tactical reconnaissance, vulnerability orchestration, and automated infrastructure auditing. Built natively in Go, Anubis leverages a stateful worker pool architecture to execute non-destructive corporate-grade security assessments with maximum throughput and microscopic latency.

**Lead Architect & Maintainer:** `Unknown Xrg`

---

## ⚡ Core Capabilities & Technical Architecture

Anubis is engineered to bypass the limitations of legacy scanners by introducing a modern engineering pipeline:

* **Stateful Worker Pool Logic:** High-speed execution driven by a managed Goroutine pool, ensuring accurate rate limits and reliable thread isolation under heavy loads.
* **Granular Lifecycle Pipeline:** Features an automated **Level 0 Pre-Scan Baseline** engine that profiles remote asset responsiveness, latency deltas, and upstream WAF/firewall stability before injecting active payloads.
* **Checkpoint & Hot-Restore Mechanism:** Interrupt continuous scanning cycles at any stage (`Ctrl+C`) and resume execution using saved telemetry checkpoints (`--resume`).
* **Multi-Format Enterprise Reporting:** Synchronized multi-format reporting outputs (`HTML`, `JSON`, `CSV`) wrapped inside high-end analytical schemas with OWASP mapping.

---

## 🛠️ Built With & Technology Stack

The framework utilizes a highly optimized, modern tech stack for cybersecurity tooling:

* **Core Engine:** **Go (Golang 1.21+)** — Chosen for its native concurrency management (Goroutines), low memory footprint, and compilation into a single self-contained binary.
* **CLI Architecture:** **Cobra Framework** — Powering the robust command-line routing, auto-generated help interfaces, and nested flagship enterprise flags.
* **Console Aesthetics:** **Fatih Color** — Injecting optimized ANSI color schemas and high-contrast logging states into stdout/stderr pipelines.

---

## 📊 Framework Inspection Profiles

The testing architecture is segmented into progressive intensity vectors, balancing stealth and comprehensive analysis:

| Profiling Tier | Intent & Description | Executed Vectors / Modules |
| :--- | :--- | :--- |
| **Level 0 (Baseline)** | Pre-Scan Evaluation | Target delta variance, latency telemetry, response stability mapping. |
| **Level 1 (Passive/Light)** | Non-Intrusive Recon | TCP Connect service mapping (`PORT_SCAN`), SSL/TLS Cipher Analysis (`SSL_CHECK`), Missing Security Headers (`HEADERS`), Passive Sensitive Discovery (`SENSITIVE_FILES`). |
| **Level 2 (Active Scan)** | Directed Auditing | DNS sub-domain brute-forcing (`DNS`), Error-based SQLi analysis (`SQLI`), Reflected XSS parsing (`XSS`), Default Credentials checking (`BRUTE_FORCE`). |
| **Level 3 (Comprehensive)**| Aggressive Fingerprinting | Deep Tech-Stack profiling (`FINGERPRINT`), Extended sensitive directory sweeps, Multi-parameter mapping. |

---

## ⚙️ Core Flags Reference

### Target Configuration
* `-t, --target <string>`: Destination URL, Domain, or IP Address string.
* `-l, --level <int>`: Operational profile depth: `1` (light), `2` (active), `3` (deep). [Default: `1`]

### Advanced Connection Layer
* `--threads <int>`: Max limit of parallel execution workers. [Default: `5`]
* `--timeout <int>`: HTTP connection link drop window in seconds. [Default: `30`]
* `--rate-limit <int>`: Minimum artificial delay interval between processing sequences (ms). [Default: `150`]
* `--proxy <url>`: Outbound traffic redirection route (e.g., `http://127.0.0.1:8080`).
* `--ssl-bypass`: Bypasses untrusted or self-signed upstream TLS validations.

### Target Authentication
* `-u, --username <string>`: Identification secret used to pass through stateful app gateways.
* `-p, --password <string>`: Credential credential secret paired with the active username.
* `--auth-strategy <string>`: Choice of routine authentication pipeline: `none`, `defaults`, `bruteforce`, `combined`.

---

## ⚔️ Tactical Production Examples

### 1. Minimal Passive Reconnaissance (Stealth Mode)
Run a quick, passive infrastructure inspection utilizing minimal system resources and zero noisy payloads:
```bash
anubis --target [https://target-infrastructure.com](https://target-infrastructure.com) --level 1
2. Authenticated Vulnerability Inspection with Output Aggregation
Execute an active audit against target layers using strict session tokens, multi-threaded concurrency, and mixed report delivery:

Bash
anubis -t [https://api.target-infrastructure.com](https://api.target-infrastructure.com) -l 2 \
       --username "security_audit_svc" --password "TokenSecretXYZ" \
       --threads 8 --format html+json --output target_corporate_report
3. Non-Interactive Massive Distributed Scanning (Batch Mode)
Feed a newline-separated target architecture file into the core engine to execute mass automated sweeps:

Bash
anubis --batch --batch-file production_scopes.txt --level 2 --rate-limit 250
4. Resuming Interrupted Testing Checkpoints
Instantly pick up where an interrupted engine cycle left off, restoring state logs and keeping generated results intact:

Bash
anubis --resume
⚖️ Legal Disclaimer & Terms
CRITICAL WARNING: This framework is engineered strictly for authorized security assessments, infrastructure defensive auditing, and legitimate contract-based penetration testing. Running aggressive network or application vulnerability sweeps against third-party digital assets without explicit, legally-binding written consent is entirely unlawful and punishable under localized and international cybercrime legislation.

The developers and contributors of this platform assume absolute zero liability for any operational down-times, damages, financial losses, or legal consequences resulting from unauthorized configurations or misuse of this software engine. Secure explicit permission prior to any operational invocation.

Unknown Xrg — Engineered for Advanced Cyber Operations and Defensive Security.
