# Anubis — Advanced Modular Web Security & Auditing Framework

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:5a0000,40:8B0000,70:ea1d25,100:ff4d4d&height=240&section=header&text=ANUBIS&fontSize=72&fontColor=ffffff&fontAlignY=38&animation=fadeIn&desc=Advanced%20Modular%20Web%20Security%20Tools&descAlignY=62&descSize=20" width="100%"/>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-000000?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Security-Authorized%20Testing-red?style=for-the-badge" alt="Security Domain">
</p>

---

## 🌐 Overview

**Anubis** is a high-performance, modular web application security framework designed for **reconnaissance, vulnerability analysis, and automated infrastructure auditing**.

Built with Go’s concurrency model at its core, Anubis delivers **low-latency, high-throughput scanning** using a stateful worker pool architecture, enabling scalable and controlled security assessments across diverse environments.

> **Maintained by:** `Unknown Xrg`

---

## ⚡ Architecture & Core Features

Anubis replaces legacy scanning limitations with a modern, concurrent execution pipeline:

* **Stateful Worker Pool Engine**
  Efficient Goroutine-based execution with strict rate control and thread isolation under heavy workloads.

* **Pre-Scan Baseline (Level 0)**
  Intelligent profiling of target stability, latency variance, and WAF behavior before active probing.

* **Checkpoint & Resume System**
  Interrupt-safe execution with real-time telemetry persistence (`--resume` supported).

* **Multi-Format Reporting**
  Export results in:

  * `HTML` (interactive dark UI)
  * `JSON`
  * `CSV`
    Includes structured vulnerability insights and remediation hints.

---

## 🛠️ Tech Stack

* **Core Engine:** Go (1.21+) — native concurrency & cross-platform binaries
* **CLI Framework:** Cobra — modular command routing & flag parsing
* **Console Output:** ANSI/Fatih — real-time visual feedback

---

## 📊 Scanning Profiles

| Level | Mode          | Description                                                         |
| ----- | ------------- | ------------------------------------------------------------------- |
| **0** | Baseline      | Latency mapping, availability checks, environment profiling         |
| **1** | Passive Recon | Port scan, SSL validation, headers audit, sensitive files detection |
| **2** | Active Scan   | SQLi, XSS, DNS enumeration, credential brute checks                 |
| **3** | Deep Audit    | Full fingerprinting, recursive directory analysis                   |

---

## 💾 Installation

### 🔹 Automated Installation (Recommended)

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/anubis.git
cd anubis

chmod +x install.sh
sudo ./install.sh
```

---

### 🔹 Manual Build

```bash
# Install dependencies
make deps

# Build binary
make build

# Install globally
make install

# Cross-platform builds
make build-all
```

---

## ⚙️ Core Flags

### Target Configuration

```bash
-t, --target <string>     Target URL, domain, or IP
-l, --level <int>         Scan depth (1–3) [default: 1]
```

### Performance & Networking

```bash
--threads <int>           Concurrent workers [default: 5]
--timeout <int>           Request timeout (seconds) [default: 30]
--rate-limit <int>        Delay between requests (ms) [default: 150]
--proxy <url>             Proxy routing
--ssl-bypass              Disable strict TLS validation
```

---

## ⚔️ Usage Examples

### Passive Recon (Stealth)

```bash
anubis -t https://target.com -l 1
```

### Authenticated Scan

```bash
anubis -t https://api.target.com -l 2 \
  --username "user" --password "secret" \
  --threads 8 \
  --format html+json \
  --output report
```

### Batch Scanning

```bash
anubis --batch --batch-file scopes.txt --level 2 --rate-limit 250
```

### Resume Previous Scan

```bash
anubis --resume
```

---

## ⚠️ Legal Disclaimer

This tool is strictly intended for:

* Authorized penetration testing
* Security research
* Defensive infrastructure auditing

**Unauthorized use against systems without explicit permission is illegal.**

The developers assume **no liability** for misuse, damages, or legal consequences resulting from improper deployment.

---

## 🧠 Philosophy

Anubis is engineered with a focus on:

* Precision over noise
* Controlled concurrency
* Real-world security workflows

---

> **Unknown Xrg**
> Engineered for Advanced Cybersecurity Operations
