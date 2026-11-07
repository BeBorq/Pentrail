package redact

import (
	"bytes"
	"regexp"
	"regexp/syntax"
)

// Codex 04AB (CPU profile of TestRedactThroughputConPTYRows in QEMU: 94% in
// finishLine, 81% in plain, 79% in FindAllSubmatchIndex): on rows that start
// with a cursor position and contain trigger words, the continuation join
// runs line() on the whole joined text — up to 4 KiB of context plus the
// row — for every row, although finishLine uses only the result for the
// row's own bytes (clean[len(prefix):]). lineTail computes exactly that part
// while scanning, per pattern, only the text from a proven restart point s
// at or before the row. Rules, the 4 KiB context, candidate overlaps and
// their order are unchanged; prefilterOff (the reference) still runs line()
// on everything.
//
// Why a restart at s is exact for one pattern (FindAll is a chain of
// leftmost-first, non-overlapping matches; patterns never match the empty
// text — each needs its literals):
//   - if no match of the chain contains both s-1 and s, the chain's matches
//     that end after s all start at or after s, and they are the leftmost-
//     first matches of the text from s on — the same text and, because the
//     scan runs on text[s-1:] with the real character before s, the same
//     \b and ^ context at s. A match that would start at that first
//     character (index 0 of the slice) is not provably the full scan's
//     match: then the full text is scanned.
//   - a chain match containing s-1 and s starts at some u < s, so text[u:s]
//     is a non-empty prefix of a string the pattern matches. tailCheck[i]
//     matches exactly when some non-empty suffix of text[:s] is such a
//     prefix (a superset: empty-width assertions after the prefix's last
//     character are dropped, which only makes it say "maybe" more often). It
//     is the pattern's non-empty-prefix expression, reversed, run anchored on
//     the reversed text from s backwards, so it stops where every partial
//     match dies instead of scanning the whole context. Its first character
//     is text[s] itself (the context of assertions at s).
//
// The check reads backwards only as far as a partial match can reach; a
// partial inside a quoted value (`"[^"\r\n]*`) reaches back to its opening
// quote, i.e. to the start of a text without quotes (ConPTY rows joined
// without line feeds). For text[:s] without '"' and '\'' the check uses
// tailCheckNoQ: the same expression with those two characters removed from
// every literal and class — for such a text exactly the same matches —
// where the quoted alternatives cannot start at all.
//
// When no restart point is proven within joinTailTries candidates, when the
// text is not ASCII (byte reversal would change runes) or contains an OSC
// sequence (line() decodes those separately), the full text is scanned —
// the same result. Quoted context goes straight to the full scan: probing
// many restart candidates inside an open quoted value can repeatedly scan
// the whole context before falling back, making it far more expensive.

const joinTailTries = 64

// tailCheck[i]: \A(?s:.)(?:reverse(nonEmptyPrefixes(patterns[i])));
// tailCheckNoQ[i]: the same without the two quote characters (for text without them).
var tailCheck, tailCheckNoQ []*regexp.Regexp

// Codex 04AE: the expressions' sources are generated (jointail_sources.go)
// instead of built at start: building them goes through syntax.Regexp's
// String(), which checks the case folding of every character class rune by
// rune — over a million runes for each negated class — and made every
// process start (even `--help`) about 0.4 s slower natively, about 5 s in
// QEMU. TestJoinTailCheckSourcesAreCurrent rebuilds them from patterns with
// tailCheckSources and requires them to be identical (regenerate with
// PENTRAIL_REGEN_JOINTAIL=1); compiling them here takes about 1 ms.
func init() {
	if len(tailCheckSrc) != len(patterns) || len(tailCheckNoQSrc) != len(patterns) {
		panic("redact: jointail_sources.go does not match the patterns")
	}
	for i := range patterns {
		tailCheck = append(tailCheck, regexp.MustCompile(`\A(?s:.)(?:`+tailCheckSrc[i]+`)`))
		tailCheckNoQ = append(tailCheckNoQ, regexp.MustCompile(`\A(?s:.)(?:`+tailCheckNoQSrc[i]+`)`))
	}
}

// tailCheckSources builds the two check expressions' sources for one pattern
// (used by the test that keeps jointail_sources.go current).
func tailCheckSources(re *regexp.Regexp) (string, string) {
	p, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		panic(err)
	}
	r := reverseRe(nonEmptyPrefix(p.Simplify()))
	return pruneNoMatch(r).String(), pruneNoMatch(withoutRunes(r, '"', '\'')).String()
}

func reNoMatch() *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpNoMatch} }

func reConcat(sub ...*syntax.Regexp) *syntax.Regexp {
	if len(sub) == 1 {
		return sub[0]
	}
	return &syntax.Regexp{Op: syntax.OpConcat, Sub: sub}
}

func reAlt(sub ...*syntax.Regexp) *syntax.Regexp {
	switch len(sub) {
	case 0:
		return reNoMatch()
	case 1:
		return sub[0]
	}
	return &syntax.Regexp{Op: syntax.OpAlternate, Sub: sub}
}

// nonEmptyPrefix: an expression for the non-empty prefixes of the strings
// re matches (assertions inside the consumed part kept, those after the
// prefix's end dropped). re must be simplified (no OpRepeat).
func nonEmptyPrefix(re *syntax.Regexp) *syntax.Regexp {
	switch re.Op {
	case syntax.OpLiteral:
		var x *syntax.Regexp
		for i := len(re.Rune) - 1; i >= 0; i-- {
			lit := &syntax.Regexp{Op: syntax.OpLiteral, Flags: re.Flags, Rune: []rune{re.Rune[i]}}
			if x == nil {
				x = lit
			} else {
				x = reConcat(lit, &syntax.Regexp{Op: syntax.OpQuest, Sub: []*syntax.Regexp{x}})
			}
		}
		if x == nil {
			return reNoMatch()
		}
		return x
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return re
	case syntax.OpCapture, syntax.OpQuest:
		return nonEmptyPrefix(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return reConcat(&syntax.Regexp{Op: syntax.OpStar, Sub: []*syntax.Regexp{re.Sub[0]}}, nonEmptyPrefix(re.Sub[0]))
	case syntax.OpConcat:
		var alts []*syntax.Regexp
		for k := range re.Sub {
			alts = append(alts, reConcat(append(append([]*syntax.Regexp(nil), re.Sub[:k]...), nonEmptyPrefix(re.Sub[k]))...))
		}
		return reAlt(alts...)
	case syntax.OpAlternate:
		var alts []*syntax.Regexp
		for _, s := range re.Sub {
			alts = append(alts, nonEmptyPrefix(s))
		}
		return reAlt(alts...)
	case syntax.OpRepeat:
		panic("redact: nonEmptyPrefix needs a simplified expression")
	}
	return reNoMatch() // empty-width assertions, empty match, no match
}

// reverseRe: an expression matching the reversed strings, with the line and
// text anchors swapped (\b is symmetric).
func reverseRe(re *syntax.Regexp) *syntax.Regexp {
	c := *re
	switch re.Op {
	case syntax.OpLiteral:
		c.Rune = make([]rune, len(re.Rune))
		for i, r := range re.Rune {
			c.Rune[len(re.Rune)-1-i] = r
		}
	case syntax.OpBeginLine:
		c.Op = syntax.OpEndLine
	case syntax.OpEndLine:
		c.Op = syntax.OpBeginLine
	case syntax.OpBeginText:
		c.Op, c.Flags = syntax.OpEndText, 0
	case syntax.OpEndText:
		c.Op, c.Flags = syntax.OpBeginText, 0
	}
	if len(re.Sub) > 0 {
		c.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, s := range re.Sub {
			c.Sub[i] = reverseRe(s)
		}
		if re.Op == syntax.OpConcat {
			for i, j := 0, len(c.Sub)-1; i < j; i, j = i+1, j-1 {
				c.Sub[i], c.Sub[j] = c.Sub[j], c.Sub[i]
			}
		}
	}
	return &c
}

// withoutRunes: re restricted to strings that contain none of rs (every
// literal containing one of them matches nothing; they are removed from
// every class). rs must not contain '\n'.
func withoutRunes(re *syntax.Regexp, rs ...rune) *syntax.Regexp {
	c := *re
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			for _, x := range rs {
				if r == x {
					return reNoMatch()
				}
			}
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL, syntax.OpCharClass:
		ranges := re.Rune
		switch re.Op {
		case syntax.OpAnyChar:
			ranges = []rune{0, 0x10ffff}
		case syntax.OpAnyCharNotNL:
			ranges = []rune{0, '\n' - 1, '\n' + 1, 0x10ffff}
		}
		for _, x := range rs {
			var next []rune
			for k := 0; k+1 < len(ranges); k += 2 {
				lo, hi := ranges[k], ranges[k+1]
				if x < lo || x > hi {
					next = append(next, lo, hi)
					continue
				}
				if lo <= x-1 {
					next = append(next, lo, x-1)
				}
				if x+1 <= hi {
					next = append(next, x+1, hi)
				}
			}
			ranges = next
		}
		if len(ranges) == 0 {
			return reNoMatch()
		}
		c.Op, c.Rune, c.Flags = syntax.OpCharClass, ranges, re.Flags&^syntax.FoldCase
	}
	if len(re.Sub) > 0 {
		c.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, s := range re.Sub {
			c.Sub[i] = withoutRunes(s, rs...)
		}
	}
	return &c
}

// pruneNoMatch: the same language without branches that can never match
// (a concatenation or repetition-of-one-or-more containing "no match" is
// "no match"; alternatives that are "no match" are dropped; a star or
// optional of "no match" matches only the empty text). The matcher would
// otherwise keep threads alive through a branch that ends in "no match".
func pruneNoMatch(re *syntax.Regexp) *syntax.Regexp {
	if len(re.Sub) == 0 {
		return re
	}
	c := *re
	c.Sub = nil
	for _, s := range re.Sub {
		s = pruneNoMatch(s)
		if s.Op == syntax.OpNoMatch {
			switch re.Op {
			case syntax.OpAlternate:
				continue
			case syntax.OpStar, syntax.OpQuest:
				return &syntax.Regexp{Op: syntax.OpEmptyMatch}
			case syntax.OpRepeat:
				if re.Min == 0 {
					return &syntax.Regexp{Op: syntax.OpEmptyMatch}
				}
				return reNoMatch()
			default: // concat, plus, capture
				return reNoMatch()
			}
		}
		c.Sub = append(c.Sub, s)
	}
	if re.Op == syntax.OpAlternate {
		return reAlt(c.Sub...)
	}
	return &c
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// tailStart: a restart point s (1 <= s <= from) proven for pattern i, or 0.
// v is ASCII, rev is v reversed, from < len(v), firstQuote is the index of
// the first '"' or '\” in v (len(v) if none). Candidates are positions after
// a non-word byte, nearest first.
func tailStart(i int, v, rev []byte, from, firstQuote int) int {
	// The proof check can walk back to a quote for every candidate. Avoid
	// multiplying that work by joinTailTries; the full scan below is already
	// the exact reference path, including matches crossing the row boundary.
	if firstQuote < from {
		return 0
	}
	tries := 0
	for s := from; s >= 1 && tries < joinTailTries; s-- {
		if isWordByte(v[s-1]) {
			continue
		}
		tries++
		check := tailCheck[i]
		if s <= firstQuote { // text[:s] has no quote
			check = tailCheckNoQ[i]
		}
		if !check.Match(rev[len(v)-1-s:]) {
			return s
		}
	}
	return 0
}

// plainTail: dst starts equal to src; afterwards dst equals plain(src) at
// every index >= from (earlier indices may differ). found must be
// litsFound(foldCanon(src)) — the literals plain() computes — so the same
// patterns run.
func plainTail(dst, src []byte, from int, found uint64, sc *scratch) {
	if from >= len(src) {
		return // no index at or after from
	}
	facts := assignmentFactsForPatterns(src, found)
	ascii := from > 0 && facts.ascii
	firstQuote := -1
	for i, re := range patterns {
		if !mayMatch(i, found) {
			continue
		}
		if fastPatternImpossible(i, facts) {
			continue
		}
		if ms, ok := fastTailMatches(i, src, from, facts); ok {
			for _, m := range ms {
				for j := 2; j < len(m); j += 2 {
					if m[j] >= 0 {
						mask(dst[m[j]:m[j+1]])
					}
				}
			}
			continue
		}
		start := 0
		if ascii {
			if firstQuote < 0 {
				sc.rev = append(sc.rev[:0], src...)
				for a, b := 0, len(src)-1; a < b; a, b = a+1, b-1 {
					sc.rev[a], sc.rev[b] = sc.rev[b], sc.rev[a]
				}
				firstQuote = facts.firstQuote
				if firstQuote < 0 {
					if firstQuote = bytes.IndexAny(src, `"'`); firstQuote < 0 {
						firstQuote = len(src)
					}
				}
			}
			start = tailStart(i, src, sc.rev, from, firstQuote)
		}
		var ms [][]int
		off := 0
		if start > 0 {
			ms, off = patternMatchesKnown(i, re, src[start-1:], facts), start-1
			if len(ms) > 0 && ms[0][0] == 0 {
				start = 0 // a match at the context character: scan everything
			}
		}
		if start == 0 {
			ms, off = patternMatchesKnown(i, re, src, facts), 0
		}
		for _, m := range ms {
			for j := 2; j < len(m); j += 2 {
				if m[j] >= 0 {
					mask(dst[off+m[j] : off+m[j+1]])
				}
			}
		}
	}
}

// lineTail returns input with the changes line(input) makes at every byte
// index >= from (earlier bytes may differ). Without an OSC sequence line()
// is: the visible text (complete CSI skipped, CR dropped), plain() on it,
// changed visible bytes written back; here plain() is plainTail from the
// first visible byte at or after from.
//
// sc must hold what quietWith(input, sc) computed (it returned false):
// the visible text and its literal bits. The result lives in sc.out until
// the next call with sc.
func lineTail(input []byte, from int, sc *scratch) []byte {
	if bytes.Contains(input, []byte("\x1b]")) {
		return line(input)
	}
	vf, positions := 0, sc.positions[:0]
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
			if i >= from {
				positions = append(positions, i)
			} else {
				vf++
			}
		}
		i++
	}
	sc.positions = positions
	visible := sc.visible
	if len(visible) != vf+len(positions) {
		panic("redact: lineTail without quietWith on the same input")
	}
	sc.clean = append(sc.clean[:0], visible...)
	plainTail(sc.clean, visible, vf, sc.found, sc)
	sc.out = append(sc.out[:0], input...)
	for k, p := range positions {
		if c := sc.clean[vf+k]; c != visible[vf+k] {
			sc.out[p] = c
		}
	}
	return sc.out
}
