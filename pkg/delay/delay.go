// Package delay provides intelligent request pacing and rate limiting
package delay

import (
	"math"
	"math/rand"
	"time"
)

// Strategy defines how delays are calculated
type Strategy int

const (
	// Fixed delay between each request
	Fixed Strategy = iota
	// Exponential backoff (doubles on each retry)
	Exponential
	// Linear backoff (adds fixed amount on each retry)
	Linear
// Random jitter (±20% around base delay)
	Jitter
)

// ParseStrategy converts a CLI flag value ("fixed", "exponential", "linear",
// "jitter") into a Strategy. Defaults to Jitter on unrecognized input rather
// than erroring, since callers should validate the flag value separately
// (see cmd/anubis/root.go) before scan dispatch — this is the safe fallback
// if that validation is ever bypassed (e.g. programmatic use of the package).
func ParseStrategy(s string) Strategy {
	switch s {
	case "fixed":
		return Fixed
	case "exponential":
		return Exponential
	case "linear":
		return Linear
	case "jitter":
		return Jitter
	default:
		return Jitter
	}
}

// Limiter manages request pacing with configurable backoff strategies
type Limiter struct {
	baseDelayMs time.Duration
	maxDelayMs  time.Duration
	strategy    Strategy
	retries     int
	lastDelay   time.Duration
}

// NewLimiter creates a rate limiter with fixed base delay
func NewLimiter(baseDelayMs int) *Limiter {
	return &Limiter{
		baseDelayMs: time.Duration(baseDelayMs) * time.Millisecond,
		maxDelayMs:  60 * time.Second,
		strategy:    Jitter,
		retries:     0,
		lastDelay:   0,
	}
}

// FromConfig builds a Limiter from the raw values carried on scanner.ScanConfig
// (RateLimit, plus the CLI-level strategy/max-delay/adaptive settings). Every
// module should construct its limiter this way instead of calling NewLimiter
// directly, so a single change to how config maps to limiter behavior doesn't
// require touching nine separate module files.
//
// adaptive is accepted here for call-site symmetry with how modules read
// config, but adaptive behavior itself lives in AdaptiveDelay — a module that
// wants adaptive pacing should construct *both* a Limiter (for the jitter/backoff
// math) and an AdaptiveDelay (for response-driven adjustment), or simply use
// AdaptiveDelay alone when --adaptive-delay is set. See RecordStatusCode below.
func FromConfig(baseDelayMs int, strategyName string, maxDelayMs int) *Limiter {
	l := NewLimiter(baseDelayMs)
	l.WithStrategy(ParseStrategy(strategyName))
	l.WithMaxDelay(maxDelayMs)
	return l
}

// RecordStatusCode is a convenience wrapper that feeds an HTTP status code
// into the retry/success counters: 429 and 5xx count as failures (triggering
// backoff growth on the next Wait()), everything else counts as success
// (resetting backoff). Modules can call this right after every request
// instead of hand-rolling the same if/else each time.
func (l *Limiter) RecordStatusCode(statusCode int) {
	if statusCode == 429 || statusCode >= 500 {
		l.RecordRetry()
		return
	}
	l.RecordSuccess()
}

// WithStrategy sets the backoff strategy
func (l *Limiter) WithStrategy(s Strategy) *Limiter {
	l.strategy = s
	return l
}

// WithMaxDelay sets the maximum delay cap
func (l *Limiter) WithMaxDelay(ms int) *Limiter {
	l.maxDelayMs = time.Duration(ms) * time.Millisecond
	return l
}

// Wait applies the current delay
func (l *Limiter) Wait() {
	delay := l.calculateDelay()
	time.Sleep(delay)
}

// WaitCh returns a channel that will close after the delay
func (l *Limiter) WaitCh() <-chan time.Time {
	delay := l.calculateDelay()
	return time.After(delay)
}

// RecordRetry increments failure counter for backoff calculation
func (l *Limiter) RecordRetry() {
	l.retries++
	if l.retries > 15 {
		l.retries = 15 // cap at 2^15
	}
}

// RecordSuccess resets the retry counter
func (l *Limiter) RecordSuccess() {
	l.retries = 0
}

// calculateDelay computes the next delay based on strategy
func (l *Limiter) calculateDelay() time.Duration {
	var delay time.Duration

	switch l.strategy {
	case Fixed:
		delay = l.baseDelayMs

	case Exponential:
		// 2^retries * baseDelay, capped
		exp := math.Pow(2.0, float64(l.retries))
		delay = time.Duration(exp) * l.baseDelayMs
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case Linear:
		// baseDelay + (retries * baseDelay), capped
		delay = l.baseDelayMs + time.Duration(l.retries)*l.baseDelayMs
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case Jitter:
		// baseDelay ± 20% random
		jitterPercent := 0.2
		delta := float64(l.baseDelayMs) * jitterPercent * (2*rand.Float64() - 1)
		delay = l.baseDelayMs + time.Duration(delta)
		if delay < 0 {
			delay = 0
		}
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}
	}

	l.lastDelay = delay
	return delay
}

// LastDelay returns the last applied delay
func (l *Limiter) LastDelay() time.Duration {
	return l.lastDelay
}

// RandomBetween returns a random duration between min and max milliseconds
func RandomBetween(minMs, maxMs int) time.Duration {
	if minMs >= maxMs {
		return time.Duration(minMs) * time.Millisecond
	}
	delta := maxMs - minMs
	random := rand.Intn(delta)
	return time.Duration(minMs+random) * time.Millisecond
}

// ExponentialBackoff returns exponential backoff delay for a given attempt number
func ExponentialBackoff(attempt int, baseMs int) time.Duration {
	exp := math.Pow(2.0, float64(attempt))
	if exp > 3600.0 {
		exp = 3600.0 // cap at 1 hour
	}
	return time.Duration(exp*float64(baseMs)) * time.Millisecond
}

// AdaptiveDelay adjusts delay based on response patterns
type AdaptiveDelay struct {
	baseMs      int
	currentMs   int
	minMs       int
	maxMs       int
	lastSuccess time.Time
}

// NewAdaptiveDelay creates an adaptive delay tracker
func NewAdaptiveDelay(baseMs, minMs, maxMs int) *AdaptiveDelay {
	return &AdaptiveDelay{
		baseMs:      baseMs,
		currentMs:   baseMs,
		minMs:       minMs,
		maxMs:       maxMs,
		lastSuccess: time.Now(),
	}
}

// Next returns the next recommended delay
func (ad *AdaptiveDelay) Next() time.Duration {
	// If we got throttled (4xx/5xx), increase delay exponentially
	// If we're seeing stable responses, gradually decrease
	sinceLast := time.Since(ad.lastSuccess)
	if sinceLast > 5*time.Second {
		// Server seems responsive, decrease delay by 10%
		ad.currentMs = int(float64(ad.currentMs) * 0.9)
		if ad.currentMs < ad.minMs {
			ad.currentMs = ad.minMs
		}
	}
	return time.Duration(ad.currentMs) * time.Millisecond
}

// RecordResponse records a response for adaptive adjustment
func (ad *AdaptiveDelay) RecordResponse(statusCode int) {
	if statusCode >= 200 && statusCode < 300 {
		ad.lastSuccess = time.Now()
		return
	}
	// 4xx/5xx or timeout: increase delay
	if statusCode >= 429 || statusCode >= 500 {
		ad.currentMs = int(float64(ad.currentMs) * 1.5)
		if ad.currentMs > ad.maxMs {
			ad.currentMs = ad.maxMs
		}
	}
}
