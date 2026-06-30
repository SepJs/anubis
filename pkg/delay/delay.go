package delay

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type Strategy int

const (
	Fixed Strategy = iota
	Exponential
	Linear
	Jitter
	RandomizedJitter
	Polymorphic
)

type Limiter struct {
	baseDelayMs time.Duration
	maxDelayMs  time.Duration
	strategy    Strategy
	retries     int
	lastDelay   time.Duration
	jitterMin   float64
	jitterMax   float64
	mu          sync.Mutex
	rng         *rand.Rand
}

func NewLimiter(baseDelayMs int) *Limiter {
	return &Limiter{
		baseDelayMs: time.Duration(baseDelayMs) * time.Millisecond,
		maxDelayMs:  60 * time.Second,
		strategy:    Jitter,
		jitterMin:   0.5,
		jitterMax:   1.5,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func FromConfig(baseDelayMs int, strategyName string, maxDelayMs int) *Limiter {
	l := NewLimiter(baseDelayMs)
	l.WithStrategy(ParseStrategy(strategyName))
	l.WithMaxDelay(maxDelayMs)
	return l
}

func (l *Limiter) RecordStatusCode(statusCode int) {
	if statusCode == 429 || statusCode >= 500 {
		l.RecordRetry()
		return
	}
	l.RecordSuccess()
}

func (l *Limiter) WithStrategy(s Strategy) *Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.strategy = s
	return l
}

func (l *Limiter) WithMaxDelay(ms int) *Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxDelayMs = time.Duration(ms) * time.Millisecond
	return l
}

func (l *Limiter) WithJitterRange(min, max float64) *Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.jitterMin = min
	l.jitterMax = max
	return l
}

func (l *Limiter) Wait() {
	delay := l.calculateDelay()
	time.Sleep(delay)
}

func (l *Limiter) WaitCh() <-chan time.Time {
	delay := l.calculateDelay()
	return time.After(delay)
}

func (l *Limiter) RecordRetry() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.retries++
	if l.retries > 15 {
		l.retries = 15
	}
}

func (l *Limiter) RecordSuccess() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.retries = 0
}

func (l *Limiter) calculateDelay() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	var delay time.Duration

	switch l.strategy {
	case Fixed:
		delay = l.baseDelayMs

	case Exponential:
		exp := math.Pow(2.0, float64(l.retries))
		delay = time.Duration(exp) * l.baseDelayMs
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case Linear:
		delay = l.baseDelayMs + time.Duration(l.retries)*l.baseDelayMs
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case Jitter:
		jitterPercent := 0.2
		delta := float64(l.baseDelayMs) * jitterPercent * (2*l.rng.Float64() - 1)
		delay = l.baseDelayMs + time.Duration(delta)
		if delay < 0 {
			delay = 0
		}
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case RandomizedJitter:
		scale := l.jitterMin + l.rng.Float64()*(l.jitterMax-l.jitterMin)
		delay = time.Duration(float64(l.baseDelayMs) * scale)
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}

	case Polymorphic:
		patterns := []func() time.Duration{
			func() time.Duration {
				base := float64(l.baseDelayMs)
				sine := math.Sin(float64(l.retries)*0.5) * base * 0.3
				return time.Duration(base + sine)
			},
			func() time.Duration {
				return time.Duration(float64(l.baseDelayMs) * (0.5 + l.rng.Float64()))
			},
			func() time.Duration {
				exp := math.Pow(1.5, float64(l.retries%10))
				return time.Duration(float64(l.baseDelayMs) * math.Min(exp, float64(l.maxDelayMs)/float64(l.baseDelayMs)))
			},
			func() time.Duration {
				return time.Duration(l.rng.Int63n(int64(l.maxDelayMs - l.baseDelayMs + 1))) + l.baseDelayMs
			},
		}
		delay = patterns[l.retries%len(patterns)]()
		if delay > l.maxDelayMs {
			delay = l.maxDelayMs
		}
		if delay < 0 {
			delay = 0
		}
	}

	l.lastDelay = delay
	return delay
}

func (l *Limiter) LastDelay() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastDelay
}

type AdaptiveDelay struct {
	baseMs      int
	currentMs   int
	minMs       int
	maxMs       int
	mu          sync.Mutex
	lastSuccess time.Time
	samples     []int
	windowSize  int
	avgLatency  float64
}

func NewAdaptiveDelay(baseMs, minMs, maxMs int) *AdaptiveDelay {
	return &AdaptiveDelay{
		baseMs:      baseMs,
		currentMs:   baseMs,
		minMs:       minMs,
		maxMs:       maxMs,
		lastSuccess: time.Now(),
		samples:     make([]int, 0, 100),
		windowSize:  20,
	}
}

func (ad *AdaptiveDelay) Next() time.Duration {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	latencyTrend := ad.computeLatencyTrend()

	switch {
	case latencyTrend > 1.5:
		ad.currentMs = int(float64(ad.currentMs) * 1.3)
	case latencyTrend < 0.5:
		ad.currentMs = int(float64(ad.currentMs) * 0.85)
	default:
		sinceLast := time.Since(ad.lastSuccess)
		if sinceLast > 5*time.Second {
			ad.currentMs = int(float64(ad.currentMs) * 0.9)
		}
	}

	if ad.currentMs < ad.minMs {
		ad.currentMs = ad.minMs
	}
	if ad.currentMs > ad.maxMs {
		ad.currentMs = ad.maxMs
	}

	return time.Duration(ad.currentMs) * time.Millisecond
}

func (ad *AdaptiveDelay) RecordResponse(statusCode int, latencyMs int) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.samples = append(ad.samples, latencyMs)
	if len(ad.samples) > ad.windowSize*2 {
		ad.samples = ad.samples[len(ad.samples)-ad.windowSize:]
	}

	if statusCode >= 200 && statusCode < 300 {
		ad.lastSuccess = time.Now()
		return
	}

	if statusCode >= 429 || statusCode >= 500 {
		ad.currentMs = int(float64(ad.currentMs) * 1.5)
		if ad.currentMs > ad.maxMs {
			ad.currentMs = ad.maxMs
		}
	}
}

func (ad *AdaptiveDelay) computeLatencyTrend() float64 {
	if len(ad.samples) < 4 {
		return 1.0
	}

	n := len(ad.samples)
	window := ad.samples[n-min(n, ad.windowSize):]
	if len(window) < 2 {
		return 1.0
	}

	var sum float64
	for _, v := range window {
		sum += float64(v)
	}
	ad.avgLatency = sum / float64(len(window))

	firstHalf := window[:len(window)/2]
	secondHalf := window[len(window)/2:]

	var firstAvg, secondAvg float64
	for _, v := range firstHalf {
		firstAvg += float64(v)
	}
	for _, v := range secondHalf {
		secondAvg += float64(v)
	}
	firstAvg /= float64(len(firstHalf))
	secondAvg /= float64(len(secondHalf))

	if firstAvg == 0 {
		return 1.0
	}
	return secondAvg / firstAvg
}

func (ad *AdaptiveDelay) CurrentDelay() int {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	return ad.currentMs
}

func (ad *AdaptiveDelay) AverageLatency() float64 {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	return ad.avgLatency
}

func RandomBetween(minMs, maxMs int) time.Duration {
	if minMs >= maxMs {
		return time.Duration(minMs) * time.Millisecond
	}
	delta := maxMs - minMs
	random := rand.Intn(delta)
	return time.Duration(minMs+random) * time.Millisecond
}

func ExponentialBackoff(attempt int, baseMs int) time.Duration {
	exp := math.Pow(2.0, float64(attempt))
	if exp > 3600.0 {
		exp = 3600.0
	}
	return time.Duration(exp*float64(baseMs)) * time.Millisecond
}

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
	case "randomized":
		return RandomizedJitter
	case "polymorphic":
		return Polymorphic
	default:
		return Jitter
	}
}
