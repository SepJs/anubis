# Anubis — Advanced Modular Web Security & Auditing Framework

<p align="center">
  <img src="https://capsule-render.vercel.app/main?type=Wave&color=ea1d25&height=180&section=header&text=ANUBIS&fontSize=65&fontColor=ffffff&fontAlignY=45&animation=twinkle" width="100%" alt="Anubis Banner" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-000000?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Security-Authorized%20Testing-red?style=for-the-badge" alt="Security Domain">
</p>

---

### 🌐 System Overview

Anubis is a enterprise-grade, concurrent web application security framework engineered for strategic reconnaissance, vulnerability orchestration, and automated infrastructure auditing. Built natively on Go's runtime environment, Anubis leverages a stateful worker pool architecture to execute complex, non-destructive tactical security assessments with ultra-low latency and maximum throughput.

**Lead Architect & Maintainer:** `Unknown Xrg`

---

## ⚡ Core Capabilities & Technical Architecture

Anubis bypasses the technical constraints of legacy network scanners by deploying a modern, stateful multi-threaded processing pipeline:

* **Stateful Worker Pool Logic:** High-speed parallel scanning loops managed dynamically via Goroutines, guaranteeing deterministic rate limits and complete thread isolation under heavy network loads.
* **Granular Lifecycle Pipeline:** Features an automated **Level 0 Pre-Scan Baseline** engine that profiles asset stability, latency variance, and upstream WAF architectures prior to injecting active payloads.
* **Checkpoint & Hot-Restore:** Real-time state logging allows operations to be forcefully interrupted (`Ctrl+C`) and instantly safely resumed later using telemetry validation (`--resume`).
* **Multi-Format Analytical Reporting:** Generates structural logs in `HTML` (Interactive Dark Theme), `JSON`, and `CSV` integrated with comprehensive vulnerability remediation matrixes.

---

## 🛠️ Infrastructure Tech Stack

* **Core Engine:** **Go (Golang 1.21+)** — Optimized for cross-platform binary distribution and native operating system thread efficiency.
* **CLI Routing Architecture:** **Cobra Framework** — Powering industrial command-line parsing, modular flag routing, and standardized help sub-menus.
* **Console Visualization:** **ANSI Fatih Engine** — Providing highly clear, high-contrast operational status streaming directly to stdout/stderr.

---

## 📊 Testing Profiles & Modules

| Profiling Tier | Operational Intent | Target Vectors & Executed Modules |
| :--- | :--- | :--- |
| **Level 0 (Baseline)** | Pre-Scan Profiling | Latency mapping, host availability delta, stability tracking. |
| **Level 1 (Passive Recon)** | Surface Inspection | `PORT_SCAN` (Top Ports), `SSL_CHECK` (Ciphers/Certs), `HEADERS` (Misconfigurations), `SENSITIVE_FILES` (Exposed backups, environments). |
| **Level 2 (Active Scan)** | Targeted Exploitation | `DNS` (Sub-domain enumeration), `SQLI` (Error-based parameters), `XSS` (Reflected vectors), `BRUTE_FORCE` (Default services credentials). |
| **Level 3 (Deep Audit)** | Full Penetration | `FINGERPRINT` (CMS/Framework tracking), Extended recursive directory paths sweeps. |

---

## 💾 Installation & Deployment Matrix

> [!TIP]
> Ensure your machine has Go installed (`go version`) before running the installation blocks below.

### Option 1: Automated Secure Deployment (Recommended)
The global installation script automatically verifies dependencies, tidies the internal module architecture, compiles the binary, and creates a symbolic system link:


# Clone the repository
git clone [https://github.com/YOUR_GITHUB_USERNAME/anubis.git](https://github.com/YOUR_GITHUB_USERNAME/anubis.git)
cd anubis

# Execute the automated deployment matrix
chmod +x install.sh
sudo ./install.sh

Option 2: Manual Enterprise Compilations
To manually inspect, build, or cross-compile the architecture using the development lifecycle configuration files:

Bash
# Synchronize core frameworks dependencies
make deps

# Compile production binary locally
make build

# Install the binary directly into your global path ($GOPATH/bin)
make install

# Cross-compile distribution folders for Linux, macOS, and Windows
make build-all
⚙️ Core Operational Flags
Target Controls
-t, --target <string>: Destination URL, Core Domain, or target IP Address string.

-l, --level <int>: Operational profile depth: 1 (light), 2 (active), 3 (deep). [Default: 1]

Advanced Connection Tuning
--threads <int>: Upper limit of parallel execution workers running concurrently. [Default: 5]

--timeout <int>: HTTP network connection link drop threshold window in seconds. [Default: 30]

--rate-limit <int>: Mandatory delay interval pacing between sequential request payloads (ms). [Default: 150]

--proxy <url>: Outbound connection routing (e.g., http://127.0.0.1:8080).

--ssl-bypass: Suspends strict upstream SSL/TLS certificate validation checks.

⚔️ Tactical Production Examples
1. Minimal Passive Reconnaissance (Stealth Mode)
Bash
anubis --target [https://target-infrastructure.com](https://target-infrastructure.com) --level 1
2. Authenticated Vulnerability Inspection with Mixed Report Delivery
Bash
anubis -t [https://api.target-infrastructure.com](https://api.target-infrastructure.com) -l 2 \
       --username "security_audit_svc" --password "TokenSecretXYZ" \
       --threads 8 --format html+json --output target_corporate_report
3. Non-Interactive Massive Distributed Scanning (Batch Mode)
Bash
anubis --batch --batch-file production_scopes.txt --level 2 --rate-limit 250
4. Telemetry Restore Operation
Bash
anubis --resume
[!CAUTION]

Legal Disclaimer & Terms of Usage
This framework is strictly engineered for authorized security assessments, defensive infrastructure auditing, and legitimate contract-based penetration testing operations. Executing aggressive vulnerability scans against external network resources without explicit, legally-binding written consent is completely unlawful and punishable under localized and international computer misuse legislations.

The developers and contributors of this platform assume absolute zero liability for any unexpected downtimes, system crashes, financial damages, or legal consequences resulting from the misuse or unauthorized deployment of this software engine. Secure appropriate clearance before invocation.

Unknown Xrg — Engineered for Advanced Cyber Operations and Defensive Security.
