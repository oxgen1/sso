// Package store keeps short-lived entries in memory under unguessable keys:
// pending WebAuthn challenges, SSO sessions and device codes. Each
// store has a size limit and a single lifetime for its entries, so memory use
// is bounded and a restart only signs people out.
package store

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

var (
	// ErrFull is returned by Put and Add when the store holds max live
	// entries.
	ErrFull = errors.New("store: full")
	// ErrExists is returned by Add when a live entry has the key already.
	ErrExists = errors.New("store: key exists")
)

// Store maps random keys to values of type V.
type Store[V any] struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]entry[V]
}

type entry[V any] struct {
	v       V
	expires time.Time
}

// New returns a store of at most max entries, each living for ttl by the
// clock now.
func New[V any](max int, ttl time.Duration, now func() time.Time) *Store[V] {
	return &Store[V]{max: max, ttl: ttl, now: now, entries: make(map[string]entry[V])}
}

// Put stores v under a new key of 128 random bits and returns the key and
// when the entry expires.
func (s *Store[V]) Put(v V) (string, time.Time, error) {
	key := rand.Text()
	expires, err := s.Add(key, v)
	if err != nil {
		return "", time.Time{}, err
	}
	return key, expires, nil
}

// Add stores v under a key the caller chose, such as a device flow's user
// code, and returns when the entry expires. Expired entries are only swept
// once the store is full, so a full store costs one pass over it per Add.
func (s *Store[V]) Add(key string, v V) (time.Time, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok && now.Before(e.expires) {
		return time.Time{}, ErrExists
	}
	if len(s.entries) >= s.max {
		for k, e := range s.entries {
			if !now.Before(e.expires) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= s.max {
			return time.Time{}, ErrFull
		}
	}
	expires := now.Add(s.ttl)
	s.entries[key] = entry[V]{v: v, expires: expires}
	return expires, nil
}

// Get returns the live entry under key and when it expires.
func (s *Store[V]) Get(key string) (V, time.Time, bool) {
	return s.get(key, false)
}

// Take is Get, and removes the entry: for anything good for one use.
func (s *Store[V]) Take(key string) (V, bool) {
	v, _, ok := s.get(key, true)
	return v, ok
}

// Delete removes the entry under key, if any.
func (s *Store[V]) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// Len is the number of entries, including expired ones not yet swept.
func (s *Store[V]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *Store[V]) get(key string, take bool) (V, time.Time, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		var zero V
		return zero, time.Time{}, false
	}
	if take || !now.Before(e.expires) {
		delete(s.entries, key)
	}
	if !now.Before(e.expires) {
		var zero V
		return zero, time.Time{}, false
	}
	return e.v, e.expires, true
}
