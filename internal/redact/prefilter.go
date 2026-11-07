package redact

import (
	"bytes"
	"math/bits"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Codex 04E: the redactor's cost. Every pattern below is matched against the
// visible text of each line, and on ConPTY output whose rows start with a
// cursor-positioning sequence the continuation join (finishLine) re-scans up
// to 4 KiB of context per row — measured 316–376 ms per 4 KiB with 15
// regular expressions. Each pattern can only match a text that contains
// certain literals; patternNeeds lists them, and a pattern whose literals
// are absent is not run. This changes no result: it skips only expressions
// that cannot match (TestPrefilterIsExact compares with running all of them).
//
// prefilterOff (tests only) runs every pattern and never takes the quiet
// fast path: the reference behaviour the tests compare with.
var prefilterOff bool

// patternNeeds[i] belongs to patterns[i]: every set must be satisfied by at
// least one of its literals. Literals are compared after Unicode simple case
// folding — the folding regexp's (?i) uses — so "PASS", "paſſ" and "pass" are
// the same (for the case-sensitive patterns this is a superset, still exact
// for skipping).
var patternNeeds = [][][]string{
	{{"http://"}, {"/?t="}},
	{{"curl", "wget"}, {"-u"}},
	{{"net"}, {"user"}},
	{{"convertto-securestring"}},
	{{"identified", "password"}, {`"`, "'"}},
	{{"cookie"}, {":"}},
	{{"password", "hasło", "haslo"}},
	{{"pass", "secret", "token", "api", "hasło", "haslo", "pwd"}, {":", "="}},
	{{"-"}, {"pass", "pwd", "token", "api", "secret", "hashes"}},
	{{"authorization"}, {":"}, {"basic", "bearer"}},
	{{"://"}, {"@"}},
	{{"<"}, {"pass", "secret", "token", "api"}, {"</"}},
	{{"sshpass", "mysql", "mariadb", "smbclient", "psexec", "hydra", "nxc", "netexec", "crackmapexec"}, {"-p"}},
	{{"akia"}},
	{{"eyj"}, {"."}},
}

// The literals, folded, each with a bit; needMasks[i][k] has the bits of the
// literals of set k of pattern i. litsFound scans a folded text ONCE and
// returns the bits of every literal it contains (one pass instead of one
// strings.Contains per literal: Codex 04F profile, 57% of the time).
var (
	foldedLits []string
	single     [256]uint64     // bit of a one-byte literal, by its byte
	byPair     [1 << 16]uint64 // bits of the longer literals, by their first two bytes
	needMasks  [][]uint64
)

func init() {
	id := map[string]int{}
	for _, sets := range patternNeeds {
		var masks []uint64
		for _, set := range sets {
			var m uint64
			for _, lit := range set {
				f := foldCanon([]byte(lit))
				k, ok := id[f]
				if !ok {
					k = len(foldedLits)
					id[f] = k
					foldedLits = append(foldedLits, f)
					if len(f) == 1 {
						single[f[0]] |= 1 << k
					} else {
						key := uint16(f[0])<<8 | uint16(f[1])
						byPair[key] |= 1 << k
					}
				}
				m |= 1 << k
			}
			masks = append(masks, m)
		}
		needMasks = append(needMasks, masks)
	}
	if len(foldedLits) > 64 {
		panic("redact: more than 64 prefilter literals")
	}
}

func litsFound(folded []byte) uint64 {
	var found uint64
	for i := 0; i+1 < len(folded); i++ {
		found |= single[folded[i]]
		for cand := byPair[uint16(folded[i])<<8|uint16(folded[i+1])] &^ found; cand != 0; cand &= cand - 1 {
			k := bits.TrailingZeros64(cand)
			if lit := foldedLits[k]; len(folded)-i >= len(lit) && string(folded[i:i+len(lit)]) == lit {
				found |= 1 << k
			}
		}
	}
	if n := len(folded); n > 0 {
		found |= single[folded[n-1]]
	}
	return found
}

// canonRune maps r to the smallest rune of its simple case-folding orbit.
func canonRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'a' <= r && r <= 'z' {
			r -= 'a' - 'A'
		}
		if r != 'K' && r != 'S' {
			return r
		}
	}
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < m {
			m = f
		}
	}
	return m
}

// foldCanon is the text with every rune replaced by canonRune (invalid
// UTF-8 becomes U+FFFD, which no literal contains).
func foldCanon(b []byte) string { return string(foldCanonAppend(nil, b)) }

// foldCanonAppend appends foldCanon(b) to dst (Codex 04L: into a reused
// buffer, no new string per call).
func foldCanonAppend(dst, b []byte) []byte {
	for len(b) > 0 {
		c := b[0]
		if c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			dst = append(dst, c)
			b = b[1:]
			continue
		}
		r, n := utf8.DecodeRune(b)
		dst = utf8.AppendRune(dst, canonRune(r))
		b = b[n:]
	}
	return dst
}

// scratch: buffers reused across calls (Codex 04L); never part of a
// Stream's state, so clones and checkpoints are unaffected. Concurrent
// streams (several terminals) each take their own from the pool.
type scratch struct {
	joined, visible, folded []byte
	found                   uint64 // quietWith: litsFound(folded) (Codex 04AB, lineTail)
	positions               []int  // lineTail
	clean, out, rev         []byte // lineTail, plainTail
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func getScratch() *scratch { return scratchPool.Get().(*scratch) }

func putScratch(sc *scratch) {
	const keep = 64 << 10 // do not keep buffers of a huge line
	if cap(sc.joined) > keep || cap(sc.visible) > keep || cap(sc.folded) > keep ||
		cap(sc.positions) > keep/8 || cap(sc.clean) > keep || cap(sc.out) > keep || cap(sc.rev) > keep {
		return
	}
	scratchPool.Put(sc)
}

// mayMatch: pattern i is not excluded by the literals found in its text.
func mayMatch(i int, found uint64) bool {
	for _, m := range needMasks[i] {
		if found&m == 0 {
			return false
		}
	}
	return true
}

// quiet reports that line(input) cannot change anything: input holds no OSC
// (line decodes and masks those separately) and no pattern can match its
// visible text. The visible text is built exactly as line builds it (a
// complete CSI is skipped, CR is dropped), folded, and checked against
// every pattern's literals; no allocation besides the folded copy. This is
// what makes the ConPTY continuation join cheap: it calls line() on up to
// 4 KiB of context for every row (Codex 04E/04F measurements).
func quiet(input []byte) bool {
	sc := getScratch()
	defer putScratch(sc)
	return quietWith(input, sc)
}

// quietWith is quiet using sc's visible and folded buffers.
func quietWith(input []byte, sc *scratch) bool {
	if bytes.Contains(input, []byte("\x1b]")) {
		return false
	}
	visible := sc.visible[:0]
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
		if input[i] != '\r' {
			visible = append(visible, input[i])
		}
		i++
	}
	// folded from the visible BYTES, as the patterns see them (a rune split
	// by a CSI is whole again here)
	sc.visible = visible
	sc.folded = foldCanonAppend(sc.folded[:0], visible)
	found := litsFound(sc.folded)
	sc.found = found
	for i := range patterns {
		if mayMatch(i, found) {
			return false
		}
	}
	return true
}
