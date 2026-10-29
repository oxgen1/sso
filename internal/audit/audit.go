// Package audit writes the audit log as a hash chain, and checks one.
//
// Each record is one JSON line holding seq, its place in the chain, and
// prev, the hex SHA-256 of the line before it (as sha256sum prints it). So
// an edited record breaks the next one's prev, and a deleted one breaks seq
// too. Each run of the IdP is its own chain: it starts with an audit_start
// record (seq 0, prev all zeros) and, if the IdP stops cleanly, ends with
// audit_stop.
//
// A chain can't show that its newest records were cut off, or that a whole
// run's chain was deleted: nothing on the host remembers them. That's what
// shipping the log off the host is for. A missing audit_stop is a hint,
// though a crash looks the same.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// Version is the record schema version, the "v" field.
const Version = 1

const (
	actionStart = "audit_start"
	actionStop  = "audit_stop"
)

// Log writes audit records to w, one Write per line.
type Log struct {
	mu   sync.Mutex
	w    io.Writer
	now  func() time.Time
	seq  uint64
	prev [sha256.Size]byte
}

// New starts a chain on w with an audit_start record.
func New(w io.Writer, now func() time.Time) (*Log, error) {
	l := &Log{w: w, now: now}
	return l, l.write(actionStart, "", "", nil)
}

// Write logs one event. reason is left out when empty; attrs are key and
// value pairs, the keys strings and the values anything encoding/json takes.
func (l *Log) Write(action, result, reason string, attrs ...any) error {
	return l.write(action, result, reason, attrs)
}

// Close ends the chain with an audit_stop record. Nothing may be written
// after it.
func (l *Log) Close() error {
	return l.write(actionStop, "", "", nil)
}

func (l *Log) write(action, result, reason string, attrs []any) error {
	if len(attrs)%2 != 0 {
		return fmt.Errorf("audit: odd number of attrs for %s", action)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var b bytes.Buffer
	b.WriteString(`{"log":"audit","v":` + strconv.Itoa(Version))
	b.WriteString(`,"seq":` + strconv.FormatUint(l.seq, 10))
	b.WriteString(`,"prev":"` + hex.EncodeToString(l.prev[:]) + `"`)
	fields := []any{"server_time", l.now().UTC().Format(time.RFC3339), "action", action}
	if result != "" {
		fields = append(fields, "result", result)
	}
	if reason != "" {
		fields = append(fields, "reason", reason)
	}
	for _, kv := range [][]any{fields, attrs} {
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return fmt.Errorf("audit: key %v for %s isn't a string", kv[i], action)
			}
			key, _ := json.Marshal(k)
			v, err := json.Marshal(kv[i+1])
			if err != nil {
				return fmt.Errorf("audit: %s for %s: %w", k, action, err)
			}
			b.WriteByte(',')
			b.Write(key)
			b.WriteByte(':')
			b.Write(v)
		}
	}
	b.WriteByte('}')
	// The chain moves on even if the write fails, so the next record shows
	// the gap rather than hiding it.
	l.prev = sha256.Sum256(b.Bytes())
	l.seq++
	b.WriteByte('\n')
	_, err := l.w.Write(b.Bytes())
	return err
}
