package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Codex 04Y: deterministic, per-session and per-phase payloads for the
// parallel-terminal scenarios. Every line is unique (session, phase, number),
// has no spaces (ConPTY may replace runs of spaces with cursor movements) and
// is shorter than 120 columns (no wrapping); the last line of a phase is its
// END marker. Private (paused) phases carry a random per-run token.

type payloadPhase struct {
	session int
	phase   string // A, L, P, B
	token   string // only for the private phase
	lines   []string
	path    string
}

func makePhase(dir string, session int, phase, token string, bytes int) (payloadPhase, error) {
	p := payloadPhase{session: session, phase: phase, token: token}
	size := 0
	for i := 0; size < bytes; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%d/%s/%d", session, phase, i)))
		l := fmt.Sprintf("S%d-%s-%06d-%s%s", session, phase, i, token, hex.EncodeToString(h[:])[:56])
		p.lines = append(p.lines, l)
		size += len(l) + 2
	}
	p.lines = append(p.lines, p.end())
	p.path = filepath.Join(dir, fmt.Sprintf("s%d-%s.txt", session, strings.ToLower(phase)))
	return p, os.WriteFile(p.path, []byte(strings.Join(p.lines, "\r\n")+"\r\n"), 0o600)
}

var (
	flatOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	flatCSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
)

// flatVisible: the stream without OSC/CSI sequences and line breaks (as
// flat50 of the Windows tests, available on every platform).
func flatVisible(s string) string {
	s = flatOSC.ReplaceAllString(s, "")
	s = flatCSI.ReplaceAllString(s, "")
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func (p payloadPhase) end() string { return fmt.Sprintf("S%d-%s-END", p.session, p.phase) }

// orderedMissing: how many of lines are not found, in order, in text (each
// after the previous one), and the first missing line.
func orderedMissing(text string, lines []string) (int, string) {
	pos, missing, first := 0, 0, ""
	for _, l := range lines {
		i := strings.Index(text[pos:], l)
		if i < 0 {
			if missing == 0 {
				first = l
			}
			missing++
			continue
		}
		pos += i + len(l)
	}
	return missing, first
}

func TestPayloadPhasesAndOrderedCheck(t *testing.T) {
	dir := t.TempDir()
	a, err := makePhase(dir, 1, "A", "", 4096)
	if err != nil {
		t.Fatal(err)
	}
	p, err := makePhase(dir, 1, "P", "TOKEN1234", 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range append(append([]string{}, a.lines...), p.lines...) {
		if strings.ContainsAny(l, " \t") || len(l) >= 120 {
			t.Fatalf("line %q: spaces or too long", l)
		}
	}
	if !strings.Contains(p.lines[0], "TOKEN1234") || strings.Contains(strings.Join(a.lines, ""), "TOKEN") {
		t.Fatal("token placement")
	}
	rendered := "\x1b[H" + strings.Join(a.lines, "\x1b[K\r\n")
	if n, _ := orderedMissing(flatVisible(rendered), a.lines); n != 0 {
		t.Fatalf("complete rendered stream: %d missing", n)
	}
	cut := strings.Replace(rendered, a.lines[7], "", 1)
	if n, first := orderedMissing(flatVisible(cut), a.lines); n != 1 || first != a.lines[7] {
		t.Fatalf("one line removed: missing %d first %q", n, first)
	}
	swapped := strings.Replace(strings.Replace(rendered, a.lines[3], "#", 1), a.lines[4], a.lines[3], 1)
	swapped = strings.Replace(swapped, "#", a.lines[4], 1)
	if n, _ := orderedMissing(flatVisible(swapped), a.lines); n == 0 {
		t.Fatal("reordered lines were accepted")
	}
}
