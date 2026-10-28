// Package ratelimit is token buckets per key, kept in memory with a limit on
// the number of keys.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter allows burst events per key at once, then one per every.
type Limiter struct {
	every time.Duration
	burst int
	max   int
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// New returns a Limiter that tracks at most max keys.
func New(every time.Duration, burst, max int, now func() time.Time) *Limiter {
	return &Limiter{every: every, burst: burst, max: max, now: now, buckets: make(map[string]*bucket)}
}

// Allow takes a token from key's bucket, and reports whether there was one.
//
// A key not yet seen gets a full bucket. When max keys are tracked, full
// buckets are dropped, as they're no different from new ones; if every
// bucket is in use, new keys are refused. That fails closed: whatever the
// limiter guards is under load from at least max addresses.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			for k, b := range l.buckets {
				if l.refill(b, now) >= float64(l.burst) {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= l.max {
				return false
			}
		}
		b = &bucket{tokens: float64(l.burst), at: now}
		l.buckets[key] = b
	}
	b.tokens = l.refill(b, now)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) refill(b *bucket, now time.Time) float64 {
	return min(float64(l.burst), b.tokens+float64(now.Sub(b.at))/float64(l.every))
}

// AddrKey is the key for a client address: the address itself for IPv4, and
// its /64 for IPv6, since one host usually has a whole /64.
func AddrKey(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a.WithZone(""), 64).Masked().String()
	}
	return a.String()
}
