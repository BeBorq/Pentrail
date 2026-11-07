package capture

import (
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

const segTok = "seg-token"

type segHarness struct {
	t      *testing.T
	seg    *cmdSegmenter
	off    int64
	rows   map[int64]store.Command // by index: last write wins (start, then end)
	writes int
	note   int64
	rec    bool
	stream strings.Builder // everything given to Output
}

func newSeg(t *testing.T) *segHarness {
	h := &segHarness{t: t, rows: map[int64]store.Command{}, rec: true}
	h.seg = newCmdSegmenter(segTok, 1, func(c store.Command) { h.rows[c.Index] = c; h.writes++ }, func(n int64) { h.note += n })
	return h
}

func prompt() string { return "\x1b]697;" + segTok + ";A\x07C:\\Users\\tester>" }

// out feeds output like the session does: while recording is paused the
// bytes reach the observer but are not recorded, the offset does not advance.
func (h *segHarness) out(s string, split bool) {
	b := []byte(s)
	if !h.rec {
		h.seg.Output(b, h.off, false)
		return
	}
	h.stream.WriteString(s)
	if !split {
		h.seg.Output(b, h.off, h.rec)
		h.off += int64(len(b))
		return
	}
	for _, v := range b {
		h.seg.Output([]byte{v}, h.off, h.rec)
		h.off++
	}
}

func (h *segHarness) in(s string, split bool) {
	if !split {
		h.seg.Input([]byte(s), h.off, h.rec)
		return
	}
	for _, v := range []byte(s) {
		h.seg.Input([]byte{v}, h.off, h.rec)
	}
}

func (h *segHarness) commands() []string {
	var out []string
	for i := int64(0); i < int64(len(h.rows)); i++ {
		c, ok := h.rows[i]
		if !ok {
			h.t.Fatalf("command indices not contiguous: %v", h.rows)
		}
		out = append(out, c.Command)
	}
	return out
}

func (h *segHarness) want(cmds ...string) {
	h.t.Helper()
	if got := h.commands(); strings.Join(got, "|") != strings.Join(cmds, "|") {
		h.t.Fatalf("commands = %q, want %q", got, cmds)
	}
}

// Codex audit (also reproduced in a real cmd.exe): pasting two lines at once
// executed both, but only the first got command metadata.
func TestCMDPastedLinesAllRecorded(t *testing.T) {
	// CR and CRLF end a line; a bare LF does not (native ConPTY evidence, see
	// TestNativeFixtureCMD and TestCMDBareLFIsNotEnter).
	for _, eol := range []string{"\r\n", "\r"} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			h.out(prompt(), split)
			h.in("echo AUDIT_FIRST"+eol+"echo AUDIT_SECOND"+eol, split)
			// cmd runs the first, prints a prompt, then reads and echoes the second
			h.out("echo AUDIT_FIRST\r\nAUDIT_FIRST\r\n\r\n"+prompt()+"echo AUDIT_SECOND\r\nAUDIT_SECOND\r\n\r\n"+prompt(), split)
			h.want("echo AUDIT_FIRST", "echo AUDIT_SECOND")
			for i, c := range []store.Command{h.rows[0], h.rows[1]} {
				if c.EndedAt == 0 || c.OutEndOff <= c.OutStartOff {
					t.Fatalf("eol %q split %v: command %d not closed by its prompt: %+v", eol, split, i, c)
				}
			}
			if h.note != 0 {
				t.Fatalf("nothing should be unattributed, got %d", h.note)
			}
		}
	}
}

func TestCMDUnicodeAndThreeLinePaste(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo zażółć\r\necho gęślą jaźń\r\nver\r\n", false)
	h.out("echo zażółć\r\nzażółć\r\n\r\n"+prompt()+"echo gęślą jaźń\r\ngęślą jaźń\r\n\r\n"+prompt()+"ver\r\n\r\nMicrosoft Windows\r\n\r\n"+prompt(), false)
	h.want("echo zażółć", "echo gęślą jaźń", "ver")
}

// A line typed while a program runs may be that program's input. It must not
// be recorded as a command unless cmd echoes it after a prompt.
func TestCMDProgramInputIsNotACommand(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("set /p X=Podaj: \r", false)
	h.out("set /p X=Podaj: \r\nPodaj: ", false)
	h.in("synthetic answer\r", false) // consumed by set /p
	h.out("synthetic answer\r\n\r\n"+prompt(), false)
	h.in("echo after\r", true)
	h.out("echo after\r\nafter\r\n\r\n"+prompt(), false)
	h.want("set /p X=Podaj: ", "echo after")
	if h.note != 1 {
		t.Fatalf("the program's input line must be counted as unattributed, got %d", h.note)
	}
}

// Text that merely occurs in the prompt or in output is not an echo.
func TestCMDNoFalseConfirmationFromPromptText(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("ping -n 3 host\rUsers\r", false)
	h.out("ping -n 3 host\r\nReply\r\n\r\n"+prompt(), false) // prompt path contains "Users"
	h.want("ping -n 3 host")
	h.out("Users\r\n'Users' is not recognized\r\n\r\n"+prompt(), false)
	h.want("ping -n 3 host", "Users")
}

// Ordinary typing with backspace keeps the typed text. A recalled line (Up
// arrow, then Enter) has no usable typed text; since 0.6.4 the command is
// what cmd echoed after its prompt — that echo is on screen, and the Enter
// key is in the input, so it is evidence, not a guess.
func TestCMDInteractiveTypingAndEditing(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("dirx", true)
	h.in("\x7f\r", true) // backspace
	h.out("dir\r\n Volume\r\n\r\n"+prompt(), false)
	h.in("\x1b[A\r", false) // history recall: text only on screen
	h.out("dir\r\n Volume\r\n\r\n"+prompt(), false)
	h.in("cd ..\r", true)
	h.out("cd ..\r\n\r\n"+prompt(), false)
	h.want("dir", "dir", "cd ..")
}

// Echo on the prompt line without any Enter in the input (e.g. a background
// program printing while the user types) is never a command.
func TestCMDEchoWithoutEnterIsNotACommand(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo half", false) // typed, no Enter
	h.out("echo half\r\nBACKGROUND NOISE\r\n", false)
	h.seg.Close(h.off)
	h.want()
}

// A bare LF is not Enter for cmd under ConPTY (native trace
// TestNativeCMDBareLF-20261029-061623.688: "echo LFNAT^_ONE\n" waited until
// a CR arrived a second later). LF neither ends nor enters the typed line.
func TestCMDBareLFIsNotEnter(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo ONE\n", false)
	if len(h.seg.queue) != 0 || string(h.seg.line) != "echo ONE" {
		t.Fatalf("LF ended or changed the line: queue=%d line=%q", len(h.seg.queue), h.seg.line)
	}
	h.out("echo ONE", false)
	h.in("\r", false)
	h.out("\r\nONE\r\n\r\n"+prompt(), false)
	h.want("echo ONE")
}

// Nothing typed while recording is off is ever attributed, even if cmd echoes
// it after recording resumes.
func TestCMDPauseNeverAttributesInput(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo one\r", false)
	h.out("echo one\r\none\r\n\r\n"+prompt(), false)
	h.seg.Reset(h.off) // off
	h.rec = false
	h.in("echo PAUSED_SECRET\r", false)
	h.out("echo PAUSED_SECRET\r\nPAUSED_SECRET\r\n\r\n"+prompt(), false)
	h.in("ping -n 9 x\recho TYPED_DURING_PAUSE\r", false)
	h.seg.Reset(h.off) // on
	h.rec = true
	h.out("ping -n 9 x\r\nReply\r\n\r\n"+prompt()+"echo TYPED_DURING_PAUSE\r\nTYPED_DURING_PAUSE\r\n\r\n"+prompt(), false)
	h.in("echo two\r", false)
	h.out("echo two\r\ntwo\r\n\r\n"+prompt(), false)
	h.want("echo one", "echo two")
}

// outputOf returns the captured output bytes of command c from the harness
// stream (the test keeps the stream to check ranges).
func (h *segHarness) rangeOf(stream string, c store.Command) string {
	if c.OutStartOff < 0 || c.OutEndOff > int64(len(stream)) || c.OutEndOff < c.OutStartOff {
		h.t.Fatalf("invalid range %d..%d (stream %d)", c.OutStartOff, c.OutEndOff, len(stream))
	}
	return stream[c.OutStartOff:c.OutEndOff]
}

// Codex iteration 02, finding 3 (native counter-example, core reproduction):
// cmd exits quickly after the last command; ConPTY never paints another
// prompt, so the last command's end is never observed. Before: EndedAt=0,
// OutEndOff=0 (the viewer showed no output for it) and the queued `exit`
// line was not counted anywhere. Now: closed at the end of the captured
// output, marked as not observed, exit status unknown; `exit` (never echoed)
// counted as unattributed, not stored as a command.
func TestCMDEOFClosesLastCommandWithFullRange(t *testing.T) {
	for _, eol := range []string{"\r\n", "\r"} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			var stream strings.Builder
			out := func(s string) { stream.WriteString(s); h.out(s, split) }
			out(prompt())
			h.in("echo AUDIT_FIRST"+eol+"echo AUDIT_SECOND"+eol+"exit"+eol, split)
			out("echo AUDIT_FIRST\r\nAUDIT_FIRST\r\n\r\n" + prompt() + "echo AUDIT_SECOND\r\nAUDIT_SECOND\r\n")
			h.seg.Close(h.off) // EOF: no further prompt, `exit` never painted
			h.want("echo AUDIT_FIRST", "echo AUDIT_SECOND")
			first, last := h.rows[0], h.rows[1]
			if first.EndReason != "" || first.EndedAt == 0 {
				t.Fatalf("first command (closed by its prompt): %+v", first)
			}
			if last.EndedAt == 0 || last.OutEndOff != h.off || last.EndReason != store.EndSessionEnded {
				t.Fatalf("eol %q split %v: last command not closed at EOF: %+v (stream end %d)", eol, split, last, h.off)
			}
			if last.Complete || last.ExitCode != -1 {
				t.Fatalf("unknown exit status presented as known: %+v", last)
			}
			if r := h.rangeOf(stream.String(), last); !strings.Contains(r, "AUDIT_SECOND") || strings.Contains(r, "echo AUDIT_SECOND") {
				t.Fatalf("output range of the last command: %q", r)
			}
			if h.note != 1 {
				t.Fatalf("the never-echoed `exit` line must be counted as unattributed, got %d", h.note)
			}
		}
	}
}

// `exit` echoed after a prompt is a confirmed command; EOF closes it.
func TestCMDEOFAfterEchoedExit(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo X\r", false)
	h.out("echo X\r\nX\r\n\r\n"+prompt(), false)
	h.in("exit\r", true)
	h.out("exit\r\n", false)
	h.seg.Close(h.off)
	h.want("echo X", "exit")
	if e := h.rows[1]; e.EndReason != store.EndSessionEnded || e.EndedAt == 0 || e.ExitCode != -1 || e.Complete {
		t.Fatalf("exit: %+v", e)
	}
	if h.note != 0 {
		t.Fatalf("unattributed %d", h.note)
	}
}

// A program reading stdin when the console closes: its input line is not a
// command (counted as unattributed), the program's command is closed at EOF.
func TestCMDEOFWhileProgramReadsStdin(t *testing.T) {
	h := newSeg(t)
	var stream strings.Builder
	out := func(s string) { stream.WriteString(s); h.out(s, false) }
	out(prompt())
	h.in("set /p V=Haslo testowe: \r", false)
	out("set /p V=Haslo testowe: \r\nHaslo testowe: ")
	h.in("synthetic-stdin-line\r", true)
	out("synthetic-stdin-line")
	h.in("partial typed without enter", true)
	h.seg.Close(h.off)
	h.want("set /p V=Haslo testowe: ")
	c := h.rows[0]
	if c.EndReason != store.EndSessionEnded || c.OutEndOff != h.off || !strings.Contains(h.rangeOf(stream.String(), c), "synthetic-stdin-line") {
		t.Fatalf("running program not closed with its full range: %+v", c)
	}
	if h.note != 1 {
		t.Fatalf("stdin line must be unattributed (1), the unsubmitted partial line ignored; got %d", h.note)
	}
}

// `pentrail off` while a command runs keeps the range recorded so far.
func TestCMDPauseClosesRunningCommand(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("ping -n 30 host\r", false)
	h.out("ping -n 30 host\r\nReply 1\r\n", false)
	pauseAt := h.off
	h.seg.Reset(pauseAt)
	h.rec = false
	h.out("Reply 2 (not recorded)\r\n\r\n"+prompt(), false)
	c := h.rows[0]
	if c.EndReason != store.EndRecordingPaused || c.OutEndOff != pauseAt || c.EndedAt == 0 || c.ExitCode != -1 {
		t.Fatalf("running command at pause: %+v", c)
	}
	if h.writes != 2 {
		t.Fatalf("writes %d (start + close at pause; nothing while paused)", h.writes)
	}
}

// Nothing open: Close writes nothing; a second Close is a no-op.
func TestCMDEOFIdle(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("echo a\r", false)
	h.out("echo a\r\na\r\n\r\n"+prompt(), false)
	w := h.writes
	h.seg.Close(h.off)
	h.seg.Close(h.off)
	if h.writes != w || h.note != 0 {
		t.Fatalf("idle EOF wrote %d rows / %d unattributed", h.writes-w, h.note)
	}
}

// off/on between prompts: the prompt painted while paused takes the first
// command typed after resuming; nothing typed while paused is attributed.
// Markers arrive early, as ConPTY sends them.
func TestCMDPromptPaintedDuringPause(t *testing.T) {
	h := newSeg(t)
	mark := "\x1b]697;" + segTok + ";A\x07"
	h.out(mark+"C:\\w>", false)
	h.in("echo one\r", false)
	h.out("echo one\r\n"+mark+"one\r\n\r\nC:\\w>", false)
	h.seg.Reset(h.off) // off
	h.rec = false
	h.in("echo PRIVATE\r", false)
	h.out("echo PRIVATE\r\n"+mark+"PRIVATE\r\n\r\nC:\\w>", false)
	h.seg.Reset(h.off) // on
	h.rec = true
	h.in("echo two\r", false)
	h.out("echo two\r\n"+mark+"two\r\n\r\nC:\\w>", false)
	h.seg.Close(h.off)
	h.want("echo one", "echo two")
	if c := h.rows[1]; !strings.Contains(h.stream.String()[c.OutStartOff:c.OutEndOff], "two") {
		t.Fatalf("range of echo two: %+v", c)
	}
}
