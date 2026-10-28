package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClock() *clock { return &clock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)} }

func TestGetTakeDelete(t *testing.T) {
	c := newClock()
	s := New[string](10, time.Minute, c.now)
	k, exp, err := s.Put("a")
	if err != nil {
		t.Fatal(err)
	}
	if want := c.t.Add(time.Minute); !exp.Equal(want) {
		t.Errorf("expires %v, want %v", exp, want)
	}
	if len(k) < 26 {
		t.Errorf("key %q is short", k)
	}
	if v, e, ok := s.Get(k); !ok || v != "a" || !e.Equal(exp) {
		t.Errorf("Get: %q %v %v", v, e, ok)
	}
	if v, ok := s.Take(k); !ok || v != "a" {
		t.Errorf("Take: %q %v", v, ok)
	}
	if _, ok := s.Take(k); ok {
		t.Error("taken twice")
	}
	k, _, _ = s.Put("b")
	s.Delete(k)
	if _, _, ok := s.Get(k); ok {
		t.Error("Get after Delete")
	}
	if _, _, ok := s.Get("nope"); ok {
		t.Error("Get of a key never stored")
	}
}

func TestExpiry(t *testing.T) {
	c := newClock()
	s := New[int](10, time.Minute, c.now)
	k, _, _ := s.Put(1)
	c.t = c.t.Add(time.Minute - time.Nanosecond)
	if _, _, ok := s.Get(k); !ok {
		t.Fatal("expired early")
	}
	c.t = c.t.Add(time.Nanosecond)
	if _, _, ok := s.Get(k); ok {
		t.Error("Get at expiry")
	}
	if s.Len() != 0 {
		t.Error("an expired entry was found but not removed")
	}
	k, _, _ = s.Put(2)
	c.t = c.t.Add(time.Hour)
	if _, ok := s.Take(k); ok {
		t.Error("Take after expiry")
	}
}

func TestFull(t *testing.T) {
	c := newClock()
	s := New[int](3, time.Minute, c.now)
	for i := range 3 {
		if _, _, err := s.Put(i); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(10 * time.Second)
	}
	if _, _, err := s.Put(3); !errors.Is(err, ErrFull) {
		t.Fatalf("Put into a full store: %v", err)
	}
	// The first entry expires: room for exactly one more.
	c.t = c.t.Add(30 * time.Second)
	if _, _, err := s.Put(3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put(4); !errors.Is(err, ErrFull) {
		t.Errorf("second Put after one expiry: %v", err)
	}
	if s.Len() != 3 {
		t.Errorf("Len %d, want 3", s.Len())
	}
}

func TestConcurrent(t *testing.T) {
	s := New[int](1000, time.Minute, time.Now)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				k, _, err := s.Put(i*100 + j)
				if err != nil {
					t.Error(err)
					return
				}
				if v, ok := s.Take(k); !ok || v != i*100+j {
					t.Errorf("Take: %d %v", v, ok)
				}
			}
		})
	}
	wg.Wait()
}

func TestAdd(t *testing.T) {
	c := newClock()
	s := New[string](2, time.Minute, c.now)
	if _, err := s.Add("ABCD", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("ABCD", "b"); !errors.Is(err, ErrExists) {
		t.Errorf("live key: %v, want ErrExists", err)
	}
	if v, _, _ := s.Get("ABCD"); v != "a" {
		t.Errorf("Add replaced a live entry: %q", v)
	}
	// An expired entry's key can be used again.
	c.t = c.t.Add(time.Minute)
	if _, err := s.Add("ABCD", "c"); err != nil {
		t.Errorf("expired key: %v", err)
	}
	if _, err := s.Add("EFGH", "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("IJKL", "e"); !errors.Is(err, ErrFull) {
		t.Errorf("full: %v, want ErrFull", err)
	}
}
