package httpsig

import (
	"sync"
	"time"
)

// NonceCache remembers the nonces of accepted write requests until their
// created + Skew, after which they can't pass the time window anyway. It's
// bounded: once it's full of live entries, writes are refused rather than
// forgetting a nonce early.
type NonceCache struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
}

func NewNonceCache(max int) *NonceCache {
	return &NonceCache{max: max, seen: make(map[string]time.Time)}
}

// use records keyID's nonce, or fails if it's already live.
func (c *NonceCache) use(keyID, nonce string, until, now time.Time) *Error {
	// Nonces are random, but keying by certificate too means one client can't
	// use up another's.
	key := keyID + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[key]; ok && now.Before(t) {
		return fail(ReasonReplay, "keyid %q nonce %q", keyID, nonce)
	}
	if len(c.seen) >= c.max {
		// Only sweep when full, so the common case stays O(1).
		for k, t := range c.seen {
			if !now.Before(t) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			return fail(ReasonNonceFull, "%d live nonces", len(c.seen))
		}
	}
	c.seen[key] = until
	return nil
}
