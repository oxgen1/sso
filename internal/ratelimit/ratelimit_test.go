package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestBurstThenRate(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	l := New(6*time.Second, 3, 10, c.now)
	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("event %d of the burst refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("allowed past the burst")
	}
	if !l.Allow("b") {
		t.Error("another key shares a's bucket")
	}
	c.t = c.t.Add(5 * time.Second)
	if l.Allow("a") {
		t.Error("allowed before a token refilled")
	}
	c.t = c.t.Add(time.Second)
	if !l.Allow("a") {
		t.Error("refused after a token refilled")
	}
	if l.Allow("a") {
		t.Error("one refill allowed two events")
	}
	// Refill stops at the burst.
	c.t = c.t.Add(time.Hour)
	for range 3 {
		l.Allow("a")
	}
	if l.Allow("a") {
		t.Error("an idle hour gave more than the burst")
	}
}

func TestMaxKeys(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	l := New(time.Second, 2, 2, c.now)
	l.Allow("a")
	l.Allow("b")
	if l.Allow("c") {
		t.Fatal("a third key was tracked while both buckets were in use")
	}
	// a and b are full again, so they can be dropped for c.
	c.t = c.t.Add(time.Second)
	if !l.Allow("c") {
		t.Fatal("full buckets weren't dropped")
	}
	if len(l.buckets) != 1 {
		t.Errorf("%d buckets, want 1", len(l.buckets))
	}
}

func TestAddrKey(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.7":             "10.0.0.7",
		"::ffff:10.0.0.7":      "10.0.0.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
	} {
		if got := AddrKey(netip.MustParseAddr(in)); got != want {
			t.Errorf("AddrKey(%s) = %s, want %s", in, got, want)
		}
	}
}
