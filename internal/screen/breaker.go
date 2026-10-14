package screen

import (
	"sync"
	"time"
)

// Breaker defaults, as barmkin-mod's register.ts sets them.
const (
	DefaultBreakerThreshold = 3
	DefaultBreakerCooldown  = 60 * time.Second
)

// breaker trips after threshold consecutive failed screens against one
// endpoint and stays open for cooldown. A screen is one event however many
// windows it asked. While open, the endpoint is not asked and the screen
// uses local scores. The failure count is not reset when the cooldown
// ends, so the first screen after it is a trial: one more failure reopens
// the breaker at once, and a success closes it.
//
// The production and shadow screens each have their own breaker per
// endpoint, so a shadow failure never degrades the production screen.
type breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func (b *breaker) open(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.Before(b.openUntil)
}

// record counts one screen's result.
func (b *breaker) record(now time.Time, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = now.Add(b.cooldown)
	}
}
