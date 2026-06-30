# Anubis v2.0 Architecture

## Design Philosophy

Anubis v2.0 is built on five core principles:

1. **Zero Detection** — Every network-level feature is designed to blend in with legitimate traffic
2. **Zero CGO** — Pure Go, fully static, cross-platform compilation
3. **Maximum Concurrency** — Lock-free atomic operations, bounded worker pools, no goroutine leaks
4. **Plugin Modularity** — Interface-based modules with discovery, registration, and priority scheduling
5. **Enterprise Readiness** — Encrypted databases, gRPC API, CVSS scoring, Homebrew/PowerShell packaging

## Package Architecture

### Core Layer
- `pkg/scanner/` — Engine, types, interfaces (generics, atomic pointers)
- `pkg/state/` — Atomic checkpoint state for resume
- `pkg/version/` — Version info, auto-update with SHA256 verification

### Evasion Layer
- `pkg/evasion/` — Jitter engine, header randomizer, packet padding, fingerprint mimicry, honeypot detection
- `pkg/proxy/` — SOCKS5/HTTP proxy rotator with health checking
- `pkg/throttle/` — Token bucket rate limiter
- `pkg/encoding/` — WAF bypass payload encoders

### Intelligence Layer
- `pkg/heuristic/` — Multi-rule heuristic analysis engine
- `pkg/discovery/` — Passive + brute-force subdomain discovery
- `pkg/delay/` — Polymorphic delay strategies and adaptive latency tracking

### Infrastructure Layer
- `pkg/db/` — AES-256-GCM encrypted SQLite history
- `pkg/cfg/` — YAML configuration engine
- `pkg/grpcapi/` — gRPC remote control interface
- `pkg/profile/` — CPU/memory/trace profiling
- `pkg/raw/` — Raw socket TCP packet crafting

### Utility Layer
- `pkg/utils/` — Logger (stdlib ANSI), HTTP client, prompt, input sanitization
- `pkg/report/` — HTML/JSON/CSV report generation with CVSS 3.1
- `pkg/baseline/` — Target baseline measurement

## Data Flow

```
CLI Flags / YAML Config
       │
       ▼
  ScanConfig ──► Engine.Run()
       │              │
       │        ┌──────┴──────┐
       │        ▼             ▼
       │   Worker Pool    Evasion Layer
       │   (goroutines)   (jitter, headers,
       │    semaphore)     padding, proxy)
       │        │             │
       │        ▼             ▼
       │   Module.Run() ──► HTTP Request
       │        │             │
       │        ▼             ▼
       │   Findings Ch ──► Response
       │        │
       │        ▼
       │   Heuristic Engine
       │   (likelihood, severity)
       │        │
       │        ▼
       │   Report Generator
       │   (HTML/JSON/CSV)
       │        │
       │        ▼
       │   Encrypted SQLite
       │   (scan history)
       │
       ▼
  Terminal Summary
```

## Anti-Detection Strategy

```
Detection Vector     │ Mitigation
─────────────────────┼─────────────────────────────────
Traffic Analysis     │ Polymorphic jitter, packet padding
Rate Limiting        │ Adaptive delay, token bucket
WAF Signatures       │ Double URL encoding, nested Base64
User-Agent Analysis  │ Browser fingerprint rotation
Header Analysis      │ cURL/Wget/Chrome profile mimicry
IP Blocking          │ SOCKS5/HTTP proxy rotation
Behavioral Analysis  │ Ghost mode, polymorphic delay patterns
DPI Inspection       │ Randomized packet padding (8-64 bytes)
Honeypot Detection   │ Signature matching, sandbox detection
Fingerprinting       │ Stripped symbols, PIE, no debug info
```
