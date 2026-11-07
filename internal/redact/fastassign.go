package redact

import (
	"bytes"
	"regexp"
)

// ASCII-only implementations of necessary conditions and assignment values.
// The original regexes remain the reference and the non-ASCII fallback. A
// changed rule automatically disables its fast path rather than changing what
// is masked. Captures below have exactly the original three-group layout.
const assignmentHeaderExpr = `(?i)\b(?:[a-z0-9_-]*(?:password|passwd|passphrase|secret|token|api[_-]?key)|hasło|haslo|pwd)\b["']?\s*[:=]\s*`
const assignmentValueExpr = `(?:"((?:\\.|[^"\\\r\n])*)"?|'([^'\r\n]*)'?|([^\s<>,;"']+))`
const quotedPasswordExpr = `(?i)\b(?:identified\s+by|with\s+password|password)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?)`
const passwordIsExpr = `(?i)\b(?:password|hasło|haslo)\s+(?:is|to)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s]+))`
const netUserExpr = `(?i)\bnet(?:\.exe)?\s+user\s+(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s]+)\s+(?:"([^"\r\n]*)"?|'([^'\r\n]*)'?|([^\s/][^\s]*))`

var fastAssignments, fastQuotedPassword, fastPasswordIs bool
var fastNetUser bool

func init() {
	fastAssignments = len(patterns) > 7 && patterns[7].String() == assignmentHeaderExpr+assignmentValueExpr
	fastQuotedPassword = len(patterns) > 4 && patterns[4].String() == quotedPasswordExpr
	fastPasswordIs = len(patterns) > 6 && patterns[6].String() == passwordIsExpr
	fastNetUser = len(patterns) > 2 && patterns[2].String() == netUserExpr
}

// Perl \s is exactly [\t\n\f\r ] (not vertical tab).
func assignmentSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

type assignmentTextFacts struct {
	ascii      bool
	words      uint8
	quotes     bool
	firstQuote int // index in the complete source; -1 means not computed
}

const (
	factPassword uint8 = 1 << iota
	factIdentified
	factWith
	factHaslo
)

func assignmentWordAt(b []byte, i int, word string) bool {
	if i+len(word) >= len(b) || !assignmentSpace(b[i+len(word)]) {
		return false
	}
	for j := 1; j < len(word); j++ {
		if foldASCII(b[i+j]) != word[j] {
			return false
		}
	}
	return true
}

// One scan shared by all rules. Omitting the leading word boundary is a
// conservative relaxation: absence proves impossibility, presence proves none.
func assignmentFacts(b []byte) assignmentTextFacts {
	f := assignmentTextFacts{ascii: true, firstQuote: len(b)}
	for i, c := range b {
		if c >= 128 {
			return assignmentTextFacts{}
		}
		switch foldASCII(c) {
		case '"', '\'':
			f.quotes = true
			if f.firstQuote == len(b) {
				f.firstQuote = i
			}
		case 'p':
			if f.words&factPassword == 0 && assignmentWordAt(b, i, "password") {
				f.words |= factPassword
			}
		case 'i':
			if f.words&factIdentified == 0 && assignmentWordAt(b, i, "identified") {
				f.words |= factIdentified
			}
		case 'w':
			if f.words&factWith == 0 && assignmentWordAt(b, i, "with") {
				f.words |= factWith
			}
		case 'h':
			if f.words&factHaslo == 0 && assignmentWordAt(b, i, "haslo") {
				f.words |= factHaslo
			}
		}
	}
	return f
}

func assignmentFactsForPatterns(b []byte, found uint64) assignmentTextFacts {
	if assignmentNeedsWords(found) {
		return assignmentFacts(b)
	}
	f := assignmentTextFacts{ascii: isASCII(b), firstQuote: -1}
	if fastNetUser && mayMatch(2, found) {
		f.firstQuote = bytes.IndexAny(b, `"'`)
		f.quotes = f.firstQuote >= 0
		if f.firstQuote < 0 {
			f.firstQuote = len(b)
		}
	}
	return f
}

func assignmentNeedsWords(found uint64) bool {
	return fastQuotedPassword && mayMatch(4, found) || fastPasswordIs && mayMatch(6, found)
}

func patternMatches(i int, re *regexp.Regexp, b []byte) [][]int {
	return patternMatchesKnown(i, re, b, assignmentFacts(b))
}

func patternMatchesKnown(i int, re *regexp.Regexp, b []byte, facts assignmentTextFacts) [][]int {
	if !prefilterOff && facts.ascii {
		switch {
		case i == 2 && fastNetUser && !facts.quotes:
			return netUserMatchesUnquotedASCII(b)
		case i == 4 && fastQuotedPassword:
			if facts.words&(factPassword|factIdentified|factWith) == 0 {
				return nil
			}
		case i == 6 && fastPasswordIs:
			if facts.words&(factPassword|factHaslo) == 0 {
				return nil
			}
		case i == 7 && fastAssignments:
			return assignmentMatchesASCII(b)
		}
	}
	return re.FindAllSubmatchIndex(b, -1)
}

func fastPatternImpossible(i int, facts assignmentTextFacts) bool {
	return !prefilterOff && facts.ascii && (i == 4 && fastQuotedPassword && facts.words&(factPassword|factIdentified|factWith) == 0 || i == 6 && fastPasswordIs && facts.words&(factPassword|factHaslo) == 0)
}

// Scan the ORIGINAL whole text and its complete non-overlapping match chain,
// but allocate results only for matches that can affect the consumed tail.
// No restart proof is needed, and discarded prefix matches still advance the
// parser normally (including quoted values swallowing later-looking keys).
func fastTailMatches(i int, b []byte, from int, facts assignmentTextFacts) ([][]int, bool) {
	if !prefilterOff && facts.ascii {
		if i == 7 && fastAssignments {
			return assignmentMatchesASCIITail(b, from), true
		}
		if i == 2 && fastNetUser && !facts.quotes {
			return netUserMatchesUnquotedASCIITail(b, from), true
		}
	}
	return nil, false
}

// With no quote anywhere in the ASCII text, both quoted username/password
// alternatives are impossible. The header is deterministic ASCII words and
// space-delimited fields; the nonempty password's first byte cannot be '/'.
func netUserMatchesUnquotedASCII(b []byte) [][]int {
	return netUserMatchesUnquotedASCIITail(b, 0)
}

func netUserMatchesUnquotedASCIITail(b []byte, from int) [][]int {
	var out [][]int
	for cursor := 0; cursor < len(b); {
		start, value, ok := netUserHeaderASCII(b, cursor)
		if !ok {
			break
		}
		cursor = value
		if value == len(b) {
			break
		}
		if b[value] == '/' {
			continue
		}
		end := value
		for end < len(b) && !assignmentSpace(b[end]) {
			end++
		}
		if end > from {
			out = append(out, []int{start, end, -1, -1, -1, -1, value, end})
		}
		cursor = end
	}
	return out
}

func netLiteralAt(b []byte, pos int, word string) bool {
	if pos+len(word) > len(b) {
		return false
	}
	for i := range word {
		if foldASCII(b[pos+i]) != word[i] {
			return false
		}
	}
	return true
}

func netUserHeaderASCII(b []byte, cursor int) (int, int, bool) {
	for start := cursor; start < len(b); start++ {
		if foldASCII(b[start]) != 'n' || start > 0 && isWordByte(b[start-1]) || !netLiteralAt(b, start, "net") {
			continue
		}
		p := start + 3
		if netLiteralAt(b, p, ".exe") {
			p += 4
		}
		if p == len(b) || !assignmentSpace(b[p]) {
			continue
		}
		for p < len(b) && assignmentSpace(b[p]) {
			p++
		}
		if !netLiteralAt(b, p, "user") {
			continue
		}
		p += 4
		if p == len(b) || !assignmentSpace(b[p]) {
			continue
		}
		for p < len(b) && assignmentSpace(b[p]) {
			p++
		}
		if p == len(b) {
			continue
		}
		for p < len(b) && !assignmentSpace(b[p]) {
			p++
		}
		if p == len(b) {
			continue
		}
		for p < len(b) && assignmentSpace(b[p]) {
			p++
		}
		return start, p, true
	}
	return 0, 0, false
}

func assignmentKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func assignmentSuffix(b []byte, word string) bool {
	if len(b) < len(word) {
		return false
	}
	b = b[len(b)-len(word):]
	for i := range b {
		if foldASCII(b[i]) != word[i] {
			return false
		}
	}
	return true
}

// A header's generic key is a maximal ASCII [a-z0-9_-] token ending in a
// credential keyword. Its first word byte is the earliest possible \b;
// leading hyphens cannot start a match. Bare haslo/pwd are separate regex
// alternatives and can only start at the final hyphen-delimited word.
func assignmentHeaderASCII(b []byte, cursor int) (int, int, bool) {
	for cursor < len(b) {
		if !assignmentKeyByte(b[cursor]) {
			cursor++
			continue
		}
		begin, lastWord := cursor, cursor
		for cursor < len(b) && assignmentKeyByte(b[cursor]) {
			if b[cursor] == '-' {
				lastWord = cursor + 1
			}
			cursor++
		}
		key := b[begin:cursor]
		generic := false
		switch foldASCII(key[len(key)-1]) {
		case 'd':
			generic = assignmentSuffix(key, "password") || assignmentSuffix(key, "passwd")
		case 'e':
			generic = assignmentSuffix(key, "passphrase")
		case 't':
			generic = assignmentSuffix(key, "secret")
		case 'n':
			generic = assignmentSuffix(key, "token")
		case 'y':
			generic = assignmentSuffix(key, "apikey") || assignmentSuffix(key, "api_key") || assignmentSuffix(key, "api-key")
		}
		start := begin
		if generic {
			for start < cursor && b[start] == '-' {
				start++
			}
		} else {
			word := b[lastWord:cursor]
			if !(len(word) == 3 && assignmentSuffix(word, "pwd") || len(word) == 5 && assignmentSuffix(word, "haslo")) {
				continue
			}
			start = lastWord
		}
		end := cursor
		if end < len(b) && (b[end] == '"' || b[end] == '\'') {
			end++
		}
		for end < len(b) && assignmentSpace(b[end]) {
			end++
		}
		if end == len(b) || b[end] != ':' && b[end] != '=' {
			continue
		}
		end++
		for end < len(b) && assignmentSpace(b[end]) {
			end++
		}
		return start, end, true
	}
	return 0, 0, false
}

func assignmentMatchesASCII(b []byte) [][]int {
	return assignmentMatchesASCIITail(b, 0)
}

func assignmentMatchesASCIITail(b []byte, from int) [][]int {
	var out [][]int
	for cursor := 0; cursor < len(b); {
		start, value, ok := assignmentHeaderASCII(b, cursor)
		if !ok {
			break
		}
		cursor = value // a failed value cannot hide a header inside this key/space suffix
		if value == len(b) {
			break
		}
		end, group := value, 2
		switch b[value] {
		case '"':
			group = 0
			value++
			end = value
			for end < len(b) {
				c := b[end]
				if c == '\\' && end+1 < len(b) && b[end+1] != '\n' {
					end += 2
					continue
				}
				if c == '"' || c == '\\' || c == '\r' || c == '\n' {
					break
				}
				end++
			}
		case '\'':
			group = 1
			value++
			end = value
			for end < len(b) && b[end] != '\'' && b[end] != '\r' && b[end] != '\n' {
				end++
			}
		default:
			for end < len(b) && !assignmentSpace(b[end]) && b[end] != '<' && b[end] != '>' && b[end] != ',' && b[end] != ';' && b[end] != '"' && b[end] != '\'' {
				end++
			}
			if end == value {
				continue
			}
		}
		fullEnd := end
		if group < 2 && fullEnd < len(b) && b[fullEnd] == b[value-1] {
			fullEnd++
		}
		if fullEnd > from {
			m := []int{start, fullEnd, -1, -1, -1, -1, -1, -1}
			m[2+2*group], m[3+2*group] = value, end
			out = append(out, m)
		}
		cursor = fullEnd
	}
	return out
}
