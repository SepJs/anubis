package evasion

import (
	"math"
	"math/rand"
	"time"
)

type JitterEngine struct {
	rng *rand.Rand
}

func NewJitterEngine() *JitterEngine {
	return &JitterEngine{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (je *JitterEngine) JitterDuration(base time.Duration, variance float64) time.Duration {
	if variance <= 0 {
		return base
	}
	delta := time.Duration(float64(base) * variance * (2*je.rng.Float64() - 1))
	result := base + delta
	if result < 0 {
		return 0
	}
	return result
}

func (je *JitterEngine) GaussianJitter(base time.Duration, stddev float64) time.Duration {
	u1 := je.rng.Float64()
	u2 := je.rng.Float64()
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	delta := time.Duration(float64(base) * stddev * z)
	result := base + delta
	if result < 0 {
		return 0
	}
	return result
}

func (je *JitterEngine) PolymorphicDelay(base time.Duration, attempt int) time.Duration {
	patterns := []func() time.Duration{
		func() time.Duration {
			return base + time.Duration(je.rng.Int63n(int64(base)))
		},
		func() time.Duration {
			f := float64(base) * (0.5 + je.rng.Float64())
			return time.Duration(f)
		},
		func() time.Duration {
			f := float64(base) * math.Sin(float64(attempt)*0.7)
			return time.Duration(math.Abs(f))
		},
	}
	idx := attempt % len(patterns)
	return patterns[idx]()
}
