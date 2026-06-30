# Changelog

## v2.0.0 — Complete Architecture Overhaul

### Architectural Core (Directive 1)
- Redesigned concurrency model: dynamic context cancellation, bounded worker pool with semaphore, zero memory leaks
- Atomic.Pointer-based global state for lock-free concurrent access
- Go Generics throughout the type system for strict typing and performance

### Evasion & Stealth (Directives 2-6)
- **Jitter Engine**: Gaussian jitter, randomized jitter (±50% variance), polymorphic delay patterns
- **IP Rotation**: SOCKS5/HTTP/HTTPS proxy rotator with health checking, automatic failover, round-robin distribution
- **User-Agent Spoofing**: Dynamic browser fingerprint randomizer — Chrome, Firefox, Safari, Edge profiles with full Sec-* headers
- **Protocol Obfuscation**: Randomized packet padding (8-64 bytes) via crypto/rand for DPI bypass
- **Fingerprint Mimicry**: cURL, Wget, Chrome header profiles — blend in with legitimate traffic
- **Adaptive Scanning**: AI-driven latency trend analysis — adjusts speed based on response patterns to avoid rate-limiting

### Anti-Detection (Directives 10-11)
- **Raw Socket Networking**: CAP_NET_RAW support for manual TCP packet crafting
- **Anti-Sandboxing**: Honeypot detector — identifies Cowrie, Dionaea, Glastopf signatures; sandbox environment detection
- **Ghost Mode**: Zero stdout output during scan, minimal request frequency

### Payload & WAF Evasion (Directive 9)
- **Payload Encoding**: Double URL encoding, nested Base64, Unicode escape, UTF-16, mixed case, null-byte injection, comment injection
- **Pre-built encoders**: SQLI encoder, XSS encoder, generic WAF bypass encoder

### Throttling & Rate Limiting (Directives 8, 12)
- **Token Bucket Algorithm**: Atomic CAS-based rate limiter with configurable capacity and refill rate
- **Adaptive Delay**: Latency-weighted backoff — 1.5x on 429/5xx, gradual decrease on success
- **Polymorphic Delay Strategy**: 4 distinct delay patterns that rotate to avoid behavioral analysis
- **Smart Retry**: Learns from 403/429 errors, auto-switches proxies and backoff strategies

### Heuristic Engine (Directive 25)
- Multi-rule decision engine: evidence strength, confidence boost, CVSS correlation, OWASP reference, remediation availability, module specificity, historical pattern matching
- Likelihood/Severity/Risk scoring for every finding
- Historical pattern tracking across scan sessions

### Modular Extensibility (Directive 7)
- Plugin-style module architecture with interface-based design
- New subdomain discovery module (DNS brute-force + passive sources)
- Module priority scheduling by severity/speed/comprehensiveness

### Reporting (Directive 20)
- **CVSS 3.1 Vector Computation**: Full vector string generation with base score
- **Risk Meter**: Visual risk assessment in HTML reports
- **Enhanced JSON/HTML/CSV**: CVSS scores, risk percentages, severity-weighted summaries

### Encrypted SQLite History (Directive 15)
- AES-256-GCM encrypted scan history database
- Full scan record persistence with findings, CVSS, and risk scores
- Historical stats and trend analysis
- Zero CGO dependency (modernc.org/sqlite)

### Configuration Engine (Directive 19)
- YAML-based configuration with scan profiles (stealth/aggressive/default)
- Evasion, proxy, database, API, and logging sub-configs
- Config validation for all parameters

### gRPC API (Directive 24)
- Remote scan control via gRPC with TLS and token authentication
- Start scan, query status, list modules endpoints
- Fully typed protocol buffer definitions

### Hardening & Security (Directives 13-14, 26)
- Input sanitization: URL validation, hostname/ip regex, path cleaning, log redaction
- Memory safety audit: all pointers verified, no undefined memory blocks
- CGO disabled globally — zero external C dependencies
- Panic recovery with crash.log — graceful degradation, never hard crash

### Build System (Directives 22-23, 28-29)
- Advanced ldflags: -s -w stripping, PIE (ASLR), -trimpath
- Cross-platform compilation: Linux amd64/arm64/386, Windows amd64/386, Darwin amd64/arm64
- SHA256 checksum generation for all release artifacts
- CPU/mem/trace profiling with profiler package
- Auto-update with checksum verification (SHA256)
- Automated man page generation
- UPX compression support
- Dependency audit

### Dependency Optimization (Directive 21)
- **REMOVED**: fatih/color (replaced with stdlib ANSI codes)
- **REMOVED**: schollz/progressbar (replaced with simple terminal output)
- **ADDED**: modernc.org/sqlite (pure Go SQLite, zero CGO)
- **ADDED**: google.golang.org/grpc (gRPC framework)
- **All remaining deps**: lightweight, audited, necessary

### Cross-Platform Zero-CGO (System Requirement)
- CGO_ENABLED=0 hardened in Makefile
- modernc.org/sqlite replaces mattn/go-sqlite3 (no CGO)
- Pure Go networking stack — no system library dependencies
- Full Windows/macOS/Linux support

----

## v1.1.0 — Auto-update, rate limiting, engine hardening

[Previous release content preserved below]

### Added
- pkg/version (version.go, updater.go): GitHub API update check, binary replacement
- CLI flags: --version, --check-update, --update
- pkg/delay: Limiter with fixed/exponential/linear/jitter strategies
- Adaptive delay on HTTP 429/5xx responses

### Changed
- All modules now use delay.Limiter for consistent rate limiting
- Scanner engine: single printer goroutine, no terminal race conditions
- Per-module context deadlines, panic recovery

### Fixed
- Concurrency bug causing indefinite scan hang
- Double-pacing issue (old sleep + new limiter)
- Terminal corruption from unsynchronized progress bar + log output

## v1.0.0 — Initial Release
- Modular scan engine with 9 modules
- Cobra CLI framework
- Baseline measurement
- JSON/HTML/CSV reporting
- State persistence for resume
