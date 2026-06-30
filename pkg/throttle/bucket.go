package throttle

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type TokenBucket struct {
	capacity   int64
	tokens     atomic.Int64
	refillRate float64
	lastRefill atomic.Int64
	mu         sync.Mutex
	maxBurst   int64
}

func NewTokenBucket(rate int, capacity int) *TokenBucket {
	tb := &TokenBucket{
		capacity:   int64(capacity),
		refillRate: float64(rate) / 1000.0,
		maxBurst:   int64(capacity),
	}
	tb.tokens.Store(int64(capacity))
	tb.lastRefill.Store(time.Now().UnixMilli())
	return tb
}

func (tb *TokenBucket) Allow() bool {
	tb.refill()
	for {
		current := tb.tokens.Load()
		if current <= 0 {
			return false
		}
		if tb.tokens.CompareAndSwap(current, current-1) {
			return true
		}
	}
}

func (tb *TokenBucket) Wait(ctx context.Context) error {
	tb.refill()
	for {
		current := tb.tokens.Load()
		if current > 0 {
			if tb.tokens.CompareAndSwap(current, current-1) {
				return nil
			}
			continue
		}

		nextRefill := time.Duration(int64(float64(1.0)/tb.refillRate*1000)+1) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(nextRefill):
			tb.refill()
		}
	}
}

func (tb *TokenBucket) TryAcquire(n int64) bool {
	tb.refill()
	for {
		current := tb.tokens.Load()
		if current < n {
			return false
		}
		if tb.tokens.CompareAndSwap(current, current-n) {
			return true
		}
	}
}

func (tb *TokenBucket) Available() int64 {
	tb.refill()
	return tb.tokens.Load()
}

func (tb *TokenBucket) SetRate(rate int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refillRate = float64(rate) / 1000.0
}

func (tb *TokenBucket) refill() {
	now := time.Now().UnixMilli()
	last := tb.lastRefill.Load()
	if now <= last {
		return
	}

	elapsed := now - last
	if !tb.lastRefill.CompareAndSwap(last, now) {
		return
	}

	tokensToAdd := int64(float64(elapsed) * tb.refillRate)
	if tokensToAdd <= 0 {
		return
	}

	for {
		current := tb.tokens.Load()
		newTokens := current + tokensToAdd
		if newTokens > tb.capacity {
			newTokens = tb.capacity
		}
		if newTokens <= current {
			return
		}
		if tb.tokens.CompareAndSwap(current, newTokens) {
			return
		}
	}
}

func (tb *TokenBucket) Capacity() int64 {
	return tb.capacity
}
