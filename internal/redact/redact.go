// Package redact removes recognizable credentials while preserving raw byte offsets.
// It is deliberately heuristic: arbitrary unlabeled secrets cannot be identified.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Version is the masking rule set applied when NEW data is written.
// masked-v3: arguments of every 697 marker (CWD, ART, FIN, D, unknown verbs)
// are sanitized, not only the token and the CMD line.
const Version = "masked-v3"

// VersionV2 data is protected on read with ProtectLegacyMarkers (only the
// marker rules changed since v2); older versions are re-masked in full.
const VersionV2 = "masked-v2"
const MaxLine = 64 << 10

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)http://(?:127\.0\.0\.1|localhost):[0-9]+/\?t=([a-f0-9]+)`),

	regexp.MustCompile(`(?i)\b(?:curl|wget)(?:\.exe)?\b[^\r\n]*?\s(?:-u|--user)(?:=|\s+)(?:"[^":\r\n]+:([^"\r\n]*)"?|'[^':\r\n]+:([^'\r\n]*)'?|[^\s:]+:([^\s]+))`),
	regexp.MustCompile(`(?i)\bnet(?:\.exe)?\s+user\s+(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s]+)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s/][^\s]*))`),
	regexp.MustCompile(`(?i)\bConvertTo-SecureString\s+(?:-String\s+)?(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?)`),
	regexp.MustCompile(`(?i)\b(?:identified\s+by|with\s+password|password)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?)`),
	regexp.MustCompile(`(?im)^\s*(?:cookie|set-cookie)\s*:\s*([^\r\n]+)`),
	regexp.MustCompile(`(?i)\b(?:password|hasło|haslo)\s+(?:is|to)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s]+))`),

	regexp.MustCompile(`(?i)\b(?:[a-z0-9_-]*(?:password|passwd|passphrase|secret|token|api[_-]?key)|hasło|haslo|pwd)\b["']?\s*[:=]\s*(?:"((?:\\.|[^"\\\r\n])*)"?|'([^'\r\n]*)'?|([^\s<>,;"']+))`),
	regexp.MustCompile(`(?i)--?(?:password|passwd|passphrase|pwd|token|api-key|client-secret|hashes)(?:=|\s+)(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s]+))`),
	regexp.MustCompile(`(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:basic|bearer)\s+([^\s;,]+)`),
	regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/]+)@`),
	regexp.MustCompile(`(?i)<(?:password|passwd|passphrase|secret|token|api[_-]?key)\b[^>]*>([^<]*)</`),
	regexp.MustCompile(`(?i)\b(?:sshpass|mysql|mariadb|smbclient|psexec(?:\.py|\.exe)?|hydra|nxc|netexec|crackmapexec)\b[^\r\n]*?\s-p(?:\s+|=)?(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s]+))`),
	regexp.MustCompile(`\b(AKIA[A-Z0-9]{16})\b`),
	regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b`),
}

func mask(b []byte) {
	for i, c := range b {
		if c != '\n' && c != '\r' {
			b[i] = '*'
		}
	}
}
func diff(a, b []byte) int64 {
	var n int64
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}
func plain(b []byte) {
	original := append([]byte(nil), b...)
	found := litsFound(foldCanonAppend(nil, original))
	facts := assignmentFactsForPatterns(original, found)
	for i, re := range patterns {
		if !prefilterOff && !mayMatch(i, found) {
			continue // its literals are absent: it cannot match (prefilter.go)
		}
		for _, m := range patternMatchesKnown(i, re, original, facts) {
			for j := 2; j < len(m); j += 2 {
				if m[j] >= 0 {
					mask(b[m[j]:m[j+1]])
				}
			}
		}
	}
}

// line masks colored text through a byte-position map and decodes CMD OSCs,
// so a secret cannot survive only because the shell base64-encoded its marker.
func line(input []byte) []byte {
	if !prefilterOff && quiet(input) {
		// Codex 04F: nothing to mask — no OSC, and no pattern's literals in
		// the visible text — so the result is the input (prefilter.go).
		return append([]byte(nil), input...)
	}
	out := append([]byte(nil), input...)
	visible := []byte{}
	positions := []int{}
	for i := 0; i < len(input); {
		if input[i] == 27 && i+1 < len(input) && input[i+1] == '[' {
			j := i + 2
			for j < len(input) && (input[j] < 0x40 || input[j] > 0x7e) {
				j++
			}
			if j < len(input) {
				i = j + 1
				continue
			}
		}
		if input[i] == 27 && i+1 < len(input) && input[i+1] == ']' {
			j := i + 2
			for j < len(input) && input[j] != 7 && !(input[j] == 27 && j+1 < len(input) && input[j+1] == '\\') {
				j++
			}
			if j == len(input) {
				mask(out[i:])
				break
			}
			payload := append([]byte(nil), input[i+2:j]...)
			if bytes.HasPrefix(payload, []byte("697;")) {
				sanitize697(payload)
			} else {
				plain(payload)
			}
			copy(out[i+2:j], payload)
			i = j + 1
			if input[j] == 27 {
				i = j + 2
			}
			continue
		}
		if input[i] != '\r' {
			positions = append(positions, i)
			visible = append(visible, input[i])
		}
		i++
	}
	clean := append([]byte(nil), visible...)
	plain(clean)
	for i, c := range clean {
		if c != visible[i] {
			out[positions[i]] = c
		}
	}
	return out
}

// markerVerbs are the 697 verbs whose name is fixed; for any other verb the
// whole remainder after the token is treated as data.
var markerVerbs = map[string]bool{"A": true, "B": true, "C": true, "D": true, "CMD": true, "CWD": true, "ART": true, "FIN": true, "P": true} // P: CMD prompt text (0.6.4)

// sanitize697 masks, in place and length-preserving, everything sensitive in
// the payload of a 697 marker ("697;<token>;<verb>[;<arg>]"): the per-session
// token, the base64 command line (decoded, masked, re-encoded) and the argument
// of every other verb (CWD, ART, FIN, D and unknown verbs). Ordinary text,
// including non-ASCII paths, is left byte-for-byte intact.
func sanitize697(payload []byte) {
	rest := payload[len("697;"):]
	semi := bytes.IndexByte(rest, ';')
	if semi < 0 {
		mask(rest) // only a token (or garbage): nothing worth keeping
		return
	}
	mask(rest[:semi])
	rest = rest[semi+1:]
	verb, arg := rest, []byte(nil)
	if k := bytes.IndexByte(rest, ';'); k >= 0 {
		verb, arg = rest[:k], rest[k+1:]
	}
	if !markerVerbs[string(verb)] {
		plain(rest) // unknown verb: the "verb" itself may be data
		return
	}
	if string(verb) == "CMD" {
		decoded, e := base64.StdEncoding.DecodeString(string(arg))
		if e != nil {
			mask(arg) // cannot inspect it: fail closed
			return
		}
		clean, _ := Text(decoded)
		encoded := base64.StdEncoding.EncodeToString(clean)
		if len(encoded) != len(arg) {
			mask(arg)
			return
		}
		copy(arg, encoded)
		return
	}
	plain(arg)
}

// ProtectLegacyMarkers applies the current 697-marker rules to bytes stored by
// masked-v2, which masked only the token and CMD. It does not modify storage;
// callers apply it on read. Length-preserving. A marker without a terminator
// inside buf is masked from its start (fail closed), so callers should pass a
// window that extends beyond the requested range (see LegacyWindow).
func ProtectLegacyMarkers(buf []byte) []byte {
	out := append([]byte(nil), buf...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != 27 || out[i+1] != ']' {
			continue
		}
		j := i + 2
		for j < len(out) && out[j] != 7 && !(out[j] == 27 && j+1 < len(out) && out[j+1] == '\\') {
			j++
		}
		if j >= len(out) {
			if bytes.HasPrefix(out[i+2:], []byte("697;")) || len(out)-(i+2) < 4 {
				mask(out[i:])
			}
			break
		}
		if bytes.HasPrefix(out[i+2:j], []byte("697;")) {
			sanitize697(out[i+2 : j])
		}
		i = j
	}
	return out
}

// LegacyWindow is how far before and after a requested range legacy reads
// look for marker boundaries (a whole terminal line is at most MaxLine).
const LegacyWindow = MaxLine

func isPrivateBegin(b []byte) bool {
	return bytes.Contains(b, []byte("-----BEGIN ")) && bytes.Contains(b, []byte("PRIVATE KEY-----"))
}
func isPrivateEnd(b []byte) bool {
	return bytes.Contains(b, []byte("-----END ")) && bytes.Contains(b, []byte("PRIVATE KEY-----"))
}

// Stream buffers one bounded line. Time-flushed and oversized lines fail closed:
// the remainder of that line is masked until LF, with original byte lengths.
type Stream struct {
	pending, prefix []byte
	context         []byte
	pem, closedLine bool
	nextSecretLine  bool
	Changed         int64
}

func (s *Stream) Feed(b []byte) []byte {
	var out []byte
	var repeated repeatedLineCache // local to this call, never serialized or shared
	for len(b) > 0 {
		n := bytes.IndexByte(b, '\n')
		end := n >= 0
		if !end {
			n = len(b)
		} else {
			n++
		}
		piece := b[:n]
		b = b[n:]
		if s.closedLine {
			if len(s.prefix) < 512 {
				k := 512 - len(s.prefix)
				if k > len(piece) {
					k = len(piece)
				}
				s.prefix = append(s.prefix, piece[:k]...)
			}
			v := append([]byte(nil), piece...)
			mask(v)
			s.Changed += diff(piece, v)
			out = append(out, v...)
			if end {
				s.update(s.prefix)
				s.closedLine = false
				s.nextSecretLine = false
				s.prefix = nil
			}
			continue
		}
		s.pending = append(s.pending, piece...)
		if len(s.pending) > MaxLine {
			out = append(out, s.Timeout()...)
			if end {
				s.closedLine = false
				s.nextSecretLine = false
				s.prefix = nil
			}
			continue
		}
		if end {
			out = append(out, s.finishLineCached(&repeated)...)
		}
	}
	return out
}
func (s *Stream) update(b []byte) {
	if isPrivateBegin(b) {
		s.pem = true
	}
	if isPrivateEnd(b) {
		s.pem = false
	}
}
func (s *Stream) finishLine() []byte {
	return s.finishLineCached(nil)
}

func (s *Stream) finishLineCached(repeated *repeatedLineCache) []byte {
	if prefilterOff {
		repeated = nil // the independent reference always computes every line
	}
	if repeated != nil {
		if repeated.matches(s) {
			s.pending = nil
			s.Changed += repeated.changed
			// Feed copies this borrowed result into its output immediately.
			return repeated.output
		}
		repeated.valid = false
		repeated.input = append(repeated.input[:0], s.pending...)
	}
	changedBefore := s.Changed
	b := s.pending
	s.pending = nil
	was := s.pem
	previousSecretLine := s.nextSecretLine
	s.nextSecretLine = false
	if isPrivateBegin(b) {
		s.pem = true
	}
	v := line(b)
	// ConPTY can redraw a wrapped label across CRLF and a cursor-position CSI.
	// Join only that redraw continuation for recognition; persist original byte offsets.
	//
	// Codex 04L (allocation profile: 93% of a step's bytes were here): the
	// joined text of each candidate overlap is built in a reused scratch
	// buffer; when it is quiet (no OSC, no pattern's literals — the
	// condition under which line() returns its input unchanged, see
	// TestPrefilterIsExact) line() is not called: the result would be the
	// joined text itself, which adds no '*' to v, i.e. score 0. Only the
	// winning overlap's joined text is kept as the next context. The
	// regexp is anchored (^, not multi-line): removing its one match at
	// the start is what ReplaceAll did. prefilterOff keeps the reference
	// behaviour (every candidate through line(), no fast path).
	sc := getScratch()
	defer putScratch(sc)
	loc := cursorContinuation.FindIndex(b)
	joinedContinuation := loc != nil && len(s.context) > 0
	nextContext := b
	if joinedContinuation {
		head := b[loc[1]:]
		best, bestOverlap := -1, 0
		upper, saturationSafe := continuationMaskUpper(b), 0
		var quietCache continuationQuietCache
		for overlap := 0; overlap <= min(64, min(len(head), len(s.context))); overlap++ {
			if overlap > 0 && !bytes.Equal(s.context[len(s.context)-overlap:], head[:overlap]) {
				continue
			}
			prefix := s.context[:len(s.context)-overlap]
			score := 0
			cachedQuiet := !prefilterOff && overlap > 0 && quietCache.enabled && quietCache.quiet(s.context, overlap)
			if !cachedQuiet {
				sc.joined = append(append(sc.joined[:0], prefix...), b...)
				if prefilterOff || !quietWith(sc.joined, sc) {
					var clean []byte
					if prefilterOff {
						clean = line(sc.joined)
					} else {
						clean = lineTail(sc.joined, len(prefix), sc) // Codex 04AB: only clean[len(prefix):] is used (jointail.go)
					}
					for i := range v {
						if clean[len(prefix)+i] == '*' && b[i] != '*' {
							v[i] = '*'
							score++
						}
					}
				} else if overlap == 0 {
					quietCache.init(s.context, b, sc.found)
				}
			}
			if score > best {
				best, bestOverlap = score, overlap
			}
			// If this candidate already masks every maskable row byte, no
			// later candidate can add a byte or win the earliest-max tie.
			// Prove a stable CSI map for ALL eligible prefixes first. The
			// reference deliberately keeps the complete overlap search.
			if !prefilterOff && score == upper {
				if saturationSafe == 0 {
					saturationSafe = -1
					if continuationSaturationSafe(s.context, b, head) {
						saturationSafe = 1
					}
				}
				if saturationSafe == 1 {
					break
				}
			}
		}
		prefix := s.context[:len(s.context)-bestOverlap]
		sc.joined = append(append(sc.joined[:0], prefix...), b...)
		nextContext = sc.joined
	}

	nextContext = bytes.TrimRight(nextContext, "\r\n")
	if len(nextContext) > 4096 {
		nextContext = nextContext[len(nextContext)-4096:]
	}
	contextUnchanged := repeated != nil && bytes.Equal(s.context, nextContext)
	s.context = append(s.context[:0], nextContext...)
	if was || s.pem || isPrivateEnd(b) || previousSecretLine {
		mask(v)
	}
	s.update(b)
	if emptySecretLabel(b) {
		s.nextSecretLine = true
	}
	s.Changed += diff(b, v)
	if repeated != nil && joinedContinuation && contextUnchanged &&
		!was && !previousSecretLine && !s.pem && !s.nextSecretLine {
		repeated.context = append(repeated.context[:0], s.context...)
		repeated.output = append(repeated.output[:0], v...)
		repeated.changed = s.Changed - changedBefore
		repeated.valid = true
	}
	return v
}
func (s *Stream) Timeout() []byte {
	if len(s.pending) == 0 {
		return nil
	}
	s.prefix = append([]byte(nil), s.pending[:min(len(s.pending), 512)]...)
	s.update(s.prefix)
	b := s.pending
	s.pending = nil
	for _, c := range b {
		if c != '*' && c != '\r' && c != '\n' {
			s.Changed++
		}
	}
	mask(b)
	s.closedLine = true
	return b
}
func (s *Stream) Finish() []byte {
	if len(s.pending) == 0 {
		return nil
	}
	return s.finishLine()
}
func Text(b []byte) ([]byte, int64) {
	s := Stream{}
	out := s.Feed(b)
	out = append(out, s.Finish()...)
	return out, diff(b, out)
}
func String(s string) string { b, _ := Text([]byte(s)); return string(b) }
func sensitive(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "password") || strings.Contains(k, "passwd") || strings.Contains(k, "passphrase") || strings.Contains(k, "secret") || strings.Contains(k, "token") || strings.Contains(k, "api_key") || strings.Contains(k, "apikey") || k == "hasło" || k == "haslo" || k == "cookie" || k == "set-cookie" || k == "pwd" || k == "authorization" || k == "proxy-authorization"
}
func walk(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if sensitive(k) {
				switch z := y.(type) {
				case string:
					x[k] = strings.Repeat("*", len([]byte(z)))
				case nil:
				default:
					x[k] = "***"
				}
			} else {
				x[k] = walk(y)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = walk(x[i])
		}
		return x
	case string:
		trim := strings.TrimSpace(x)
		if (strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[")) && json.Valid([]byte(trim)) {
			b, e := JSON([]byte(trim))
			if e == nil {
				return string(b)
			}
		}
		return String(x)
	default:
		return v
	}
}

// JSON sanitizes exactly one JSON document. Anything after it other than
// whitespace (a second document, a damaged tail) is an error: accepting only
// the first document would silently drop the rest of the input.
func JSON(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	if tok, e := d.Token(); e != io.EOF {
		if e != nil {
			return nil, fmt.Errorf("json: invalid data after the document: %w", e)
		}
		return nil, fmt.Errorf("json: unexpected data after the document (%v)", tok)
	}
	return json.Marshal(walk(v))
}

// Seal sanitizes a partial boundary and keeps recognized credential continuation
// masked after a pause. Ordinary non-sensitive text is not discarded.
func (s *Stream) Seal() []byte {
	old := append([]byte(nil), s.pending...)
	source := completeOSC.ReplaceAll(old, nil)
	_, visibleChanges := Text(source)
	out := s.Finish()
	tail := strings.ToLower(strings.TrimSpace(string(source)))
	tail = strings.TrimLeft(tail, "-\"'")
	if i := strings.LastIndexAny(tail, " \t:;="); i >= 0 {
		tail = tail[i+1:]
	}
	sensitiveTail := false
	for _, word := range []string{"password", "passwd", "passphrase", "secret", "token", "authorization", "bearer", "basic", "api_key"} {
		if tail != "" && strings.HasPrefix(word, tail) {
			sensitiveTail = true
		}
	}
	// A boundary right after ESC would let the rest of an escape sequence (a
	// marker with its token and arguments) arrive as plain text.
	if visibleChanges > 0 || sensitiveTail || emptySecretLabel(source) || bytes.HasSuffix(old, []byte{27}) {
		s.closedLine = true
		s.prefix = append([]byte(nil), old[:min(len(old), 512)]...)
	}
	return out
}

func (s *Stream) FailClosedBoundary() { s.closedLine = true; s.prefix = nil }

var emptyLabel = regexp.MustCompile(`(?i)(?:password|passwd|passphrase|hasło|haslo|secret|token|api[_-]?key)\s*[:=]\s*$`)

// emptySecretLabel: the line ends with a secret label and its separator
// and nothing after it (the value follows on the next line).
//
// Codex 04T (profile: 30% of a step natively, 67% in QEMU — an unanchored
// match over every line): the expression can only match if the trimmed
// text ENDS with ':' or '='. After bytes.TrimSpace the text ends in a
// non-space rune, and emptyLabel's trailing `\s*$` matches only ASCII
// space characters (all removed by TrimSpace), so the last byte must be the
// `[:=]` itself. Every other line is answered false without running the
// expression; for the rest the same expression decides. prefilterOff keeps
// the reference behaviour (always run it).
func emptySecretLabel(b []byte) bool {
	t := bytes.TrimSpace(b)
	if !prefilterOff && (len(t) == 0 || t[len(t)-1] != ':' && t[len(t)-1] != '=') {
		return false
	}
	return emptyLabel.Match(t)
}

var cursorContinuation = regexp.MustCompile(`^\x1b\[[0-9;?]*[ -/]*[HfGABCD]`)

var completeOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
