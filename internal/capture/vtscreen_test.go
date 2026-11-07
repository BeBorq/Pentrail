package capture

import (
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// vtTestScreen adds, for tests only, a transcript: the lines that scrolled off
// (collected through the onScrollOff hook) plus the screen. Production keeps
// no history.
type vtTestScreen struct {
	*vtScreen
	gone []string
}

func newVTTestScreen(w, h int) *vtTestScreen {
	ts := &vtTestScreen{vtScreen: newVTScreen(w, h)}
	ts.onScrollOff = func(t string, ok bool) {
		if ok {
			ts.gone = append(ts.gone, t)
		}
	}
	return ts
}

// transcript renders scrolled-off lines plus the screen as text lines
// (logical lines joined): "what the user saw".
func (ts *vtTestScreen) transcript() []string {
	out := append([]string{}, ts.gone...)
	seen := map[*vtLine]bool{}
	for _, r := range ts.rows {
		if r.line == nil {
			out = append(out, strings.TrimRight(strings.Join(r.cells, ""), "\x00 "))
			continue
		}
		if seen[r.line] {
			continue
		}
		seen[r.line] = true
		out = append(out, r.line.text())
	}
	return out
}

func screenOf(w, h int, chunks ...string) *vtTestScreen {
	s := newVTTestScreen(w, h)
	var off int64
	for _, c := range chunks {
		s.Feed([]byte(c), off, 0)
		off += int64(len(c))
	}
	return s
}

// ConPTY's rendering of an echo that reaches the last column at the bottom
// row (native trace, set /p): it scrolls with CRLF, moves back onto the same
// cell and rewrites it. A terminal shows one "s", not two.
func TestVTWrapRepaintAtBottomRow(t *testing.T) {
	s := screenOf(10, 3, "\x1b[3;1H123456789", "s", "\r\n\x1b[2;10Hset /p\r\n", "NEXT")
	tr := s.transcript()
	if !contains(tr, "123456789set /p") || contains(tr, "123456789sset /p") {
		t.Fatalf("transcript %q", tr)
	}
}

func TestVTCursorEraseAndUTF8Split(t *testing.T) {
	s := screenOf(20, 5, "abc\x1b[2;1Hdef\x1b[1;2H\x1b[K", "Z\xc5", "\xbbX\x1b[?25l")
	tr := strings.Join(s.transcript(), "|")
	if !strings.Contains(tr, "aZŻX") || !strings.Contains(tr, "def") {
		t.Fatalf("transcript %q", tr)
	}
}

func TestVTWideRunesAndOSCCallback(t *testing.T) {
	s := newVTTestScreen(4, 2)
	var got []string
	s.onOSC = func(p string, a, b int64) { got = append(got, p) }
	s.Feed([]byte("日本\x1b]0;title\x07x\x1b]697;t;A\x1b\\"), 0, 0)
	tr := screenText(s)
	if len(got) != 2 || got[0] != "0;title" || got[1] != "697;t;A" || !strings.Contains(tr, "日本") {
		t.Fatalf("osc %q screen %q", got, tr)
	}
}

func screenText(s *vtTestScreen) string { return strings.Join(s.transcript(), "|") }

func contains(lines []string, l string) bool {
	for _, x := range lines {
		if x == l {
			return true
		}
	}
	return false
}

// The marker with prompt text keeps the stored stream length (masking is
// length-preserving) and its token is masked.
func TestPromptMarkerTextMasking(t *testing.T) {
	in := "\x1b]697;secret-token-123;A\x07\x1b]697;secret-token-123;P;C:\\Users\\x>\x07C:\\Users\\x>"
	out, _ := redact.Text([]byte(in))
	if len(out) != len(in) || strings.Contains(string(out), "secret-token-123") {
		t.Fatalf("masked %q", out)
	}
}
