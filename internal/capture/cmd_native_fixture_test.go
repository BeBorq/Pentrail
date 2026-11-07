package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex iteration 04B: regression test on the AUTHENTIC native Windows traces
// recorded by the 04A diagnostics (testdata/native-cmd-codex-04a, synthetic
// data; local paths replaced with same-length fictional values before
// publication, SHA256.json = hashes of the sanitized files, see testdata/README.md).
//
// Every trace is replayed through the current segmenter and must give the
// correct result for what cmd actually did. The rows the session wrote LIVE
// (recorded in the trace by the 0.6.3 code) are checked too: they must show
// the defect that was reported, which proves the fixture reproduces it.

const fixtureDir = "testdata/native-cmd-codex-04a"

type fixtureCmd struct {
	text  string
	token string // must be in this command's output range ("" = none)
}

// echoedOnScreen renders raw like a terminal (with scrollback) and reports
// whether some logical line ends with the command as cmd echoed it. This is
// the explicit terminal mapping that replaces strings.Contains(raw, cmd):
// ConPTY splits an echo with OSC markers and cursor/visibility sequences and
// repaints a wrapped cell, and trims trailing blanks.
func echoedOnScreen(raw []byte, cmd string) bool {
	s := newVTTestScreen(cmdCols, cmdRows)
	s.Feed(raw, 0, 0)
	want := strings.TrimSpace(cmd)
	for _, l := range s.transcript() {
		if strings.HasSuffix(strings.TrimRight(l, " "), want) {
			return true
		}
	}
	return false
}

func checkFixture(t *testing.T, dir string, want []fixtureCmd, unattributed int64, stdin []string) *cmdReplay {
	t.Helper()
	r, err := replayCMD(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "raw.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(r.stream) {
		t.Fatalf("raw.bin %d bytes, traced output %d", len(raw), len(r.stream))
	}
	if echoedOnScreen(raw, "echo NEVER^_TYPED") {
		t.Fatal("screen check is not discriminating")
	}
	if int64(len(r.final)) != int64(len(want)) {
		t.Fatalf("%d commands, want %d: %v", len(r.final), len(want), r.got)
	}
	var prevEnd int64
	for i, w := range want {
		c, ok := r.final[int64(i)]
		if !ok {
			t.Fatalf("command index %d missing: %v", i, r.got)
		}
		if c.Command != w.text {
			t.Fatalf("#%d is %q, want %q", i, c.Command, w.text)
		}
		if c.ExitCode != -1 || c.Complete {
			t.Fatalf("#%d %q claims an exit status: %+v", i, c.Command, c)
		}
		if c.EndedAt == 0 || c.OutEndOff < c.OutStartOff || c.OutEndOff > int64(len(raw)) {
			t.Fatalf("#%d %q not closed with a valid range: %+v", i, c.Command, c)
		}
		if c.OutStartOff < prevEnd {
			t.Fatalf("#%d %q range %d..%d overlaps the previous one (ends %d)", i, c.Command, c.OutStartOff, c.OutEndOff, prevEnd)
		}
		prevEnd = c.OutEndOff
		out := raw[c.OutStartOff:c.OutEndOff]
		if w.token != "" && !bytes.Contains(out, []byte(w.token)) {
			t.Fatalf("#%d %q: range %d..%d lacks its output %q: %q", i, c.Command, c.OutStartOff, c.OutEndOff, w.token, out)
		}
		for j, o := range want { // nothing of another command's output
			if j != i && o.token != "" && o.token != w.token && bytes.Contains(out, []byte(o.token)) {
				t.Fatalf("#%d %q: range contains %q, the output of #%d", i, c.Command, o.token, j)
			}
		}
		if !echoedOnScreen(raw, c.Command) {
			t.Fatalf("#%d %q: no such echo on the rendered screen", i, c.Command)
		}
		last := i == len(want)-1
		if last != (c.EndReason == store.EndSessionEnded) || (!last && c.EndReason != "") {
			t.Fatalf("#%d %q end reason %q", i, c.Command, c.EndReason)
		}
		for _, s := range stdin {
			if strings.Contains(c.Command, s) {
				t.Fatalf("program input %q recorded as command #%d", s, i)
			}
		}
	}
	if r.gotNotes != unattributed {
		t.Fatalf("unattributed lines %d, want %d", r.gotNotes, unattributed)
	}
	return r
}

func TestNativeFixtureCMDBareLF(t *testing.T) {
	dir := filepath.Join(fixtureDir, "TestNativeCMDBareLF-20261029-061623.688")
	r := checkFixture(t, dir, []fixtureCmd{
		{"echo LFNAT^_ONE", "LFNAT_ONE"},
		{"echo LFNAT^_END", "LFNAT_END"},
		{"exit", ""},
	}, 0, nil)
	// what 0.6.3 wrote live: #0 ended at the early marker, holding only the
	// echo; #1 had an empty range
	raw, _ := os.ReadFile(filepath.Join(dir, "raw.bin"))
	l0, l1 := r.live[0], r.live[1]
	if string(raw[l0.OutStartOff:l0.OutEndOff]) != "echo LFNAT^_ONE\r\n" || l1.OutStartOff != l1.OutEndOff {
		t.Fatalf("fixture does not show the reported defect: %+v %+v", l0, l1)
	}
}

func TestNativeFixtureCMDPasteSplitUnicodeStdin(t *testing.T) {
	dir := filepath.Join(fixtureDir, "TestNativeCMDPasteSplitUnicodeStdinAndFinalCommand-20261029-061621.491")
	r := checkFixture(t, dir, []fixtureCmd{
		{"echo NAT^_ONE", "NAT_ONE"},            // typed in two frames, split inside a word
		{"echo NAT^_TWO", "NAT_TWO"},            // CR, then a separate LF frame
		{"echo NAT^_THREE", "NAT_THREE"},        // CRLF in one frame
		{"echo ŻÓŁĆ^_gęślą^_ü", "ŻÓŁĆ_gęślą_ü"}, // UTF-8 split inside "Ó"
		{"echo NAT^_P1", "NAT_P1"},              // pasted block of three lines
		{"echo NAT^_P2", "NAT_P2"},
		{"echo NAT^_P3", "NAT_P3"},
		{"set /p V=PODAJ^_TEKST: ", "synthetic-stdin-line"}, // its stdin is ITS output
		{"echo NAT^_FINAL", "NAT_FINAL"},
		{"exit", ""}, // typed together with FINAL; cmd exited at once
	}, 1, []string{"synthetic-stdin-line"})
	// what 0.6.3 wrote live: 8 rows, P3 and set /p missing, empty ranges
	if len(r.live) != 8 || r.liveNotes != 3 {
		t.Fatalf("fixture does not show the reported defect: %d live rows, %d unattributed", len(r.live), r.liveNotes)
	}
	for _, c := range r.live {
		if c.Command == "echo NAT^_P3" || strings.HasPrefix(c.Command, "set /p") {
			t.Fatalf("live rows unexpectedly contain %q", c.Command)
		}
	}
	if l := r.live[0]; l.OutStartOff != l.OutEndOff {
		t.Fatalf("live #0 range was not empty: %+v", l)
	}
}

// Codex 04E: authentic native trace of TestNativeCMDOutputImitatingPrompt
// (testdata/native-cmd-codex-04d; local paths replaced with same-length
// fictional values before publication, see testdata/README.md). After
// resize(100,30) and resize(120,30) ConPTY repaints the whole screen IN PLACE
// (CUP + text + EL per row, no clear); at 100 columns the long `cd /d` line
// takes one row more, so every following row shifts down, and back up at 120.
// 0.6.5 kept each row's old logical line, so the repainted prompt the user
// then typed at belonged to a line already decided "not the candidate", and
// `echo AFTER^_RESIZE` — executed, visible — was never recorded. Text painted
// from column 0 (not by autowrap) is now a new logical line.
func TestNativeFixtureCMDResizeRepaint(t *testing.T) {
	dir := filepath.Join("testdata", "native-cmd-codex-04d", "TestNativeCMDOutputImitatingPrompt-20261030-223234.458")
	cd := `cd /d "C:\Users\user1\AppData\Local\Temp\TestNativeCMDOutputImitatingPrompt2813931216\001"`
	r := checkFixture(t, dir, []fixtureCmd{
		{cd, ""},
		{"type fake.txt", "FAKE_HEAD"},
		{"echo NEXT^_CMD", "NEXT_CMD"},
		{"echo AFTER^_RESIZE", "AFTER_RESIZE"},
		{"exit", ""},
	}, 0, nil)
	raw, _ := os.ReadFile(filepath.Join(dir, "raw.bin"))
	// no false boundary inside the prompt-like file
	tf := r.final[1]
	for _, tok := range []string{"whoami", "net user", "FAKE_TAIL"} {
		if !bytes.Contains(raw[tf.OutStartOff:tf.OutEndOff], []byte(tok)) {
			t.Fatalf("type fake.txt: %q not in its range %d..%d", tok, tf.OutStartOff, tf.OutEndOff)
		}
	}
	// the repaints after the resizes belong to no command's output (the
	// screen showed again what was there); NEXT keeps the end it had at its
	// prompt, before the resizes
	if n := r.final[2]; n.OutEndOff > 1558 {
		t.Fatalf("echo NEXT^_CMD's end moved into the resize repaint: %+v", n)
	}
	// the defect, as the live 0.6.5 session wrote it
	if len(r.live) != 4 || r.live[3].Command != "exit" {
		t.Fatalf("fixture does not show the reported defect: %+v", r.live)
	}
	for _, c := range r.live {
		if c.Command == "echo AFTER^_RESIZE" {
			t.Fatalf("live rows unexpectedly contain the resize command")
		}
	}
}
