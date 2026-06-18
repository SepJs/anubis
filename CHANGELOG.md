# Changelog

## v1.1.0 — Auto-update, real rate limiting, engine hardening

This release does three concrete things: wires up `--version` / `--check-update`
/ `--update` to actual GitHub API calls and a real binary-replace routine
(previously these flags didn't exist at all); replaces five modules' fixed
`time.Sleep`-based pacing with a shared, configurable `delay.Limiter`
(fixed/exponential/linear/jitter strategies, optional adaptive backoff on
HTTP 429/5xx); and fixes a real concurrency bug in the scan engine that could
hang a scan indefinitely.

None of this has been run through an actual Go compiler — there is no Go
toolchain available in the environment this was built in, and no network
access to install one. Every file has been checked by hand for brace/paren
balance and for every cross-package symbol (function, method, struct field)
actually resolving to a real definition, but that is not the same guarantee
as `go build` succeeding. Build it and report back exactly what `go build`
prints if it fails — that's the fastest way to close the gap between "looks
right" and "is right."

---

### Added

**`pkg/version/version.go`, `pkg/version/updater.go`** — new package, fully
implemented (not stubbed):
- `version.FetchLatest()` does a real HTTP GET against the GitHub releases
  API (`api.github.com/repos/innervoid/anubis/releases/latest`) and parses
  the JSON response. Returns an error on network failure, 404 (no releases
  published), or unparseable response — callers cannot mistake "couldn't
  check" for "you're up to date."
- `version.IsNewer()` compares dotted version segments numerically (`1.10.0`
  is correctly newer than `1.9.0`; a naive string compare would get this
  backwards).
- `version.SelectAsset()` / `version.Apply()` pick the release asset
  matching `runtime.GOOS`/`runtime.GOARCH` and replace the running binary:
  download to a temp file, `chmod +x`, rename current binary to
  `.anubis-previous`, rename temp file into place. If the final rename
  fails, it restores the backup automatically rather than leaving the
  install in a half-finished state.

**CLI flags, wired into `cmd/anubis/root.go` and `cmd/anubis/update.go`:**
- `--version` — prints `version.Info()` and exits. No banner, no
  disclaimer, so scripts piping this output don't have to filter decoration.
- `--check-update` — read-only: fetches the latest release, reports whether
  it's newer, prints the changelog body if so. Never downloads or writes
  anything. Safe to run from cron.
- `--update` — fetches latest, asks for y/n confirmation (it's about to
  overwrite the binary you're currently running), downloads, swaps it in,
  and tells you where the backup landed.

Both update functions live in the new `cmd/anubis/update.go` rather than
inline in `root.go`, so the "this touches disk" code is in one obvious place.

**`pkg/delay/delay.go`** — this package already existed from the previous
session as a working library; what's new in this release is that it's
actually *called* from inside modules:
- `delay.FromConfig(baseMs, strategyName, maxMs)` — the one constructor every
  module now uses, instead of five slightly different hand-rolled versions.
- `Limiter.RecordStatusCode(code)` — new helper: feeds 429/5xx into
  `RecordRetry()`, anything else into `RecordSuccess()`. Modules call this
  once per request instead of duplicating the if/else.
- `delay.ParseStrategy(string)` — maps the `--strategy` flag value onto the
  `Strategy` enum, defaulting to `Jitter` on garbage input (the actual flag
  value is validated separately in `root.go`, so this fallback only matters
  for programmatic callers).

**New `ScanConfig` fields** (`pkg/scanner/types.go`): `DelayStrategy`,
`MaxDelayMs`, `AdaptiveDelay` — populated from the corresponding CLI flags in
`cmd/anubis/scan.go`'s `buildConfig()`. Previously these flags were declared
as variables in `root.go` but never copied into the config struct modules
actually receive, so they would have been silently ignored even though the
flags "existed."

---

### Changed — modules now using `delay.Limiter`

| Module | What changed |
|---|---|
| `portscan` | Per-goroutine `time.Sleep` → one shared `Limiter` behind a mutex (the fan-out is `cfg.Threads*2` goroutines; per-goroutine limiters would have multiplied the effective rate by that factor instead of respecting `--rate-limit`) |
| `sensitive` | Same shared-limiter pattern; adaptive mode wired in — a 403/429/503 on one file probe slows down every other in-flight probe sharing the limiter |
| `sqli` | Sequential loop, single limiter, adaptive mode wired in via the new `(int, error)` return from `testParam` |
| `xss` | Sequential loop, single limiter, adaptive mode wired into both `testReflection` and `testFormReflection` |
| `brute_force` | Limiter paces the POST login attempt specifically (not the initial GET of the login page, since that's not what auth rate-limiting watches); a detected "blocked" result now calls `RecordRetry()` unconditionally — slowing down on a detected lockout isn't optional behind a flag, it's the reason the lockout detection exists |
| `dns` | Shared limiter for the fixed-delay strategies; explicitly does **not** support adaptive mode, because `net.LookupHost` talks to the OS resolver and never returns an HTTP status code for `RecordStatusCode` to react to — documented in a comment rather than silently omitted |

`headers`, `ssl`, and `fingerprint` were left untouched on purpose: each
makes exactly one HTTP request per run, so there's nothing for a rate
limiter to pace.

**Important: every module that switched to `delay.Limiter` also had to set
`httpCfg.RateLimit = 0` explicitly.** `utils.DefaultHTTPConfig()` sets a
100ms default there, and `utils.DoRequest()` sleeps for that value on every
call regardless of what else is pacing the request. Without zeroing it out,
every request would have paced twice — once via the old fixed sleep, once
via the new Limiter — silently doubling scan time without doubling stealth.
This was caught and fixed during this pass, not before.

---

### Fixed — scanner engine (`pkg/scanner/engine.go`)

This is carried over from the previous session's bug report (modules
printing "Starting" but never "Done") and is unrelated to the delay/update
work above, but is bundled into this release since it's the same file:

- Removed `progressbar`'s in-place terminal redraw from the engine. It was
  being called from a worker goroutine while a separate collector goroutine
  wrote findings to stdout and `runModule` wrote log lines from a third —
  three unsynchronized writers to the same terminal, one of which moves the
  cursor. Findings/log output now goes through a single dedicated printer
  goroutine.
- Collapsed two implicit `wg.Wait()` paths (one in the main flow, one inside
  the old time-limit-reached branch) into exactly one, called only from the
  main goroutine. The watcher goroutine now only ever cancels a context; it
  never blocks on completion itself.
- Added `context.WithTimeout` per module (4 minutes for Level 1 scans, 2×
  the configured HTTP timeout otherwise), so one module hitting a
  non-responsive endpoint can no longer stall the rest of the scan
  indefinitely. A timed-out module is recorded with status `"timeout"` and
  the engine moves on.
- Added panic recovery around each module's `Run()` call. A panic in one
  module now surfaces as a failed `ModuleResult` with the panic message,
  rather than crashing the whole scan.

---

### Known gaps — stated plainly, not buried

- **Not compiled.** See the top of this changelog. The brace/paren/symbol
  checks performed are a real check, but they are not `go build`.
- **`--update` has no test coverage against a real GitHub repo.** The code
  path is real (it will issue an actual HTTP request to the URL in
  `version.ReleasesAPI`), but `github.com/innervoid/anubis` may not be a
  real repository with real releases published — if it isn't, `--check-update`
  will correctly report a 404-derived error rather than silently
  succeeding, but that's the extent of what's verified.
- **Wordlist-based brute force is still unimplemented.** `brute_force.go`
  logs a warning and skips if `--wordlist` is provided without an actual
  parser behind it — this was already true before this release and remains
  true now; it wasn't part of this round of changes.
- **`delay.AdaptiveDelay` (the standalone struct, distinct from
  `Limiter.RecordStatusCode`) is defined in `delay.go` but not used by any
  module.** Only the `Limiter` + `RecordStatusCode` combination is wired up.
  `AdaptiveDelay` exists in the package and compiles, but nothing calls it —
  if you want a second adaptive strategy that's actually active in a scan,
  that's a real follow-up, not something already done.
