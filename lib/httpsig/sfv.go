package httpsig

// This file parses and serializes the part of RFC 8941 (Structured Field
// Values) that the profile uses, and nothing else:
//
//	Signature-Input: sig1=("@method" ...);created=1;expires=2;nonce="n";keyid="k";tag="t"
//	Signature:       sig1=:<base64>:
//	Content-Digest:  sha-256=:<base64>:
//	Sso-Cert:        :<base64>:
//
// Only the canonical form is accepted: one dictionary member, single spaces
// in the inner list, no item parameters, no escapes in strings, no booleans,
// decimals or tokens, and padded base64. So whatever parses serializes back
// to exactly the input (the fuzzers check this), and the @signature-params
// line can't differ between the two sides.

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

var errSyntax = errors.New("outside the structured-field subset")

type param struct {
	key   string
	str   string
	num   int64
	isNum bool
}

// sigInput is one Signature-Input member: label=("item" ...);key=value...
type sigInput struct {
	label  string
	items  []string
	params []param
}

func parseSigInput(s string) (sigInput, error) {
	c := cursor{s: s}
	var in sigInput
	var ok bool
	if in.label, ok = c.key(); !ok || !c.next('=') || !c.next('(') {
		return sigInput{}, errSyntax
	}
	for !c.next(')') {
		if len(in.items) > 0 && !c.next(' ') {
			return sigInput{}, errSyntax
		}
		item, ok := c.str()
		if !ok {
			return sigInput{}, errSyntax
		}
		in.items = append(in.items, item)
	}
	for !c.done() {
		var p param
		if !c.next(';') {
			return sigInput{}, errSyntax
		}
		if p.key, ok = c.key(); !ok || !c.next('=') {
			return sigInput{}, errSyntax
		}
		if c.peek('"') {
			p.str, ok = c.str()
		} else {
			p.num, ok = c.integer()
			p.isNum = true
		}
		if !ok {
			return sigInput{}, errSyntax
		}
		in.params = append(in.params, p)
	}
	return in, nil
}

// value serializes the inner list and its parameters: the Signature-Input
// member's value and the @signature-params line of the signature base.
func (in sigInput) value() string {
	var b strings.Builder
	b.WriteByte('(')
	for i, item := range in.items {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(`"` + item + `"`)
	}
	b.WriteByte(')')
	for _, p := range in.params {
		b.WriteString(";" + p.key + "=")
		if p.isNum {
			b.WriteString(strconv.FormatInt(p.num, 10))
		} else {
			b.WriteString(`"` + p.str + `"`)
		}
	}
	return b.String()
}

// parseBytesMember parses key=:<base64>:.
func parseBytesMember(s string) (string, []byte, error) {
	c := cursor{s: s}
	key, ok := c.key()
	if !ok || !c.next('=') {
		return "", nil, errSyntax
	}
	b, ok := c.bytes()
	if !ok || !c.done() {
		return "", nil, errSyntax
	}
	return key, b, nil
}

// parseBytes parses a bare :<base64>: item.
func parseBytes(s string) ([]byte, error) {
	c := cursor{s: s}
	b, ok := c.bytes()
	if !ok || !c.done() {
		return nil, errSyntax
	}
	return b, nil
}

func serializeBytes(b []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(b) + ":"
}

// validString reports whether s can be serialized as a string in the subset.
func validString(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e || s[i] == '"' || s[i] == '\\' {
			return false
		}
	}
	return true
}

type cursor struct {
	s string
	i int
}

func (c *cursor) done() bool { return c.i == len(c.s) }

func (c *cursor) peek(b byte) bool { return c.i < len(c.s) && c.s[c.i] == b }

func (c *cursor) next(b byte) bool {
	if c.peek(b) {
		c.i++
		return true
	}
	return false
}

// key is lcalpha or "*", then lcalpha, digits, "_", "-", "." or "*".
func (c *cursor) key() (string, bool) {
	start := c.i
	if c.done() || (!isLower(c.s[c.i]) && c.s[c.i] != '*') {
		return "", false
	}
	for c.i++; c.i < len(c.s); c.i++ {
		ch := c.s[c.i]
		if !isLower(ch) && !isDigit(ch) && !strings.ContainsRune("_-.*", rune(ch)) {
			break
		}
	}
	return c.s[start:c.i], true
}

// str reads a string with no escapes: printable ASCII other than " and \.
func (c *cursor) str() (string, bool) {
	if !c.next('"') {
		return "", false
	}
	start := c.i
	for ; c.i < len(c.s); c.i++ {
		switch ch := c.s[c.i]; {
		case ch == '"':
			c.i++
			return c.s[start : c.i-1], true
		case ch == '\\' || ch < 0x20 || ch > 0x7e:
			return "", false
		}
	}
	return "", false
}

// integer reads a non-negative integer of at most 15 digits with no leading
// zeros.
func (c *cursor) integer() (int64, bool) {
	start := c.i
	for c.i < len(c.s) && isDigit(c.s[c.i]) {
		c.i++
	}
	digits := c.s[start:c.i]
	if len(digits) == 0 || len(digits) > 15 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	return n, err == nil
}

// bytes reads :<base64>: with padding. Go's decoder skips CR and LF, so the
// result is re-encoded and compared to rule those (and any other
// non-canonical spelling) out.
func (c *cursor) bytes() ([]byte, bool) {
	if !c.next(':') {
		return nil, false
	}
	end := strings.IndexByte(c.s[c.i:], ':')
	if end < 0 {
		return nil, false
	}
	enc := c.s[c.i : c.i+end]
	c.i += end + 1
	b, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || base64.StdEncoding.EncodeToString(b) != enc {
		return nil, false
	}
	return b, true
}

func isLower(b byte) bool { return 'a' <= b && b <= 'z' }
func isDigit(b byte) bool { return '0' <= b && b <= '9' }
