package capture

import (
	"strings"
	"testing"
)

// Codex 04C, finding 2: output that imitates the prompt. ConPTY passes the
// next prompt's marker through BEFORE it paints the tail of the finished
// command's output (native traces, 04B), so while that tail is painted a
// marker is pending. A line of that output which looks like the prompt (a
// remote target's text, a log, a file with "C:\path>" lines) must not end the
// command, must not become a command, and must not make the NEXT command or
// its output disappear.
//
// Every scenario is run with whole chunks and byte by byte.

const fakeCWD = `C:\Users\tester>`

func mark() string { return "\x1b]697;" + segTok + ";A\x07" }

func markP(text string) string {
	return "\x1b]697;" + segTok + ";A\x07\x1b]697;" + segTok + ";P;" + text + "\x07"
}

// outOf returns the recorded output of command i.
func (h *segHarness) outOf(i int64) string {
	h.t.Helper()
	c, ok := h.rows[i]
	if !ok {
		h.t.Fatalf("no command %d: %v", i, h.commands())
	}
	s := h.stream.String()
	if c.OutStartOff < 0 || c.OutEndOff > int64(len(s)) || c.OutEndOff < c.OutStartOff {
		h.t.Fatalf("command %d invalid range %d..%d", i, c.OutStartOff, c.OutEndOff)
	}
	return s[c.OutStartOff:c.OutEndOff]
}

func (h *segHarness) mustContain(i int64, toks ...string) {
	h.t.Helper()
	r := h.outOf(i)
	for _, tok := range toks {
		if !strings.Contains(r, tok) {
			h.t.Fatalf("command %d %q: range lacks %q: %q", i, h.rows[i].Command, tok, r)
		}
	}
}

func (h *segHarness) mustNotContain(i int64, toks ...string) {
	h.t.Helper()
	r := h.outOf(i)
	for _, tok := range toks {
		if strings.Contains(r, tok) {
			h.t.Fatalf("command %d %q: range contains %q: %q", i, h.rows[i].Command, tok, r)
		}
	}
}

// The file printed by `type` contains a prompt-shaped line. Its marker
// arrives before the output is painted (ConPTY order).
func TestCMDOutputImitatingPromptMarkerFirst(t *testing.T) {
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(prompt(), split)
		h.in("type notes.txt\r", split)
		h.out("type notes.txt\r\n", split)
		h.out(mark(), split) // the next prompt, announced before the output is painted
		h.out("FILE_HEAD\r\n"+fakeCWD+"whoami\r\nnt authority\\system\r\nFILE_TAIL\r\n\r\n"+fakeCWD, split)
		h.in("echo NEXT^_CMD\r", split)
		h.out("echo NEXT^_CMD\r\n", split)
		h.out(mark(), split)
		h.out("NEXT_CMD\r\n\r\n"+fakeCWD, split)
		h.seg.Close(h.off)
		h.want("type notes.txt", "echo NEXT^_CMD")
		h.mustContain(0, "FILE_HEAD", "whoami", "nt authority", "FILE_TAIL")
		h.mustContain(1, "NEXT_CMD")
		h.mustNotContain(1, "FILE_TAIL")
		if h.note != 0 {
			t.Fatalf("split %v: unattributed %d", split, h.note)
		}
	}
}

// Same, but the authentic marker arrives in the SAME output chunk, after the
// imitation and before the real prompt; also with the imitation alone on its
// line ("C:\Users\tester>" and nothing else).
func TestCMDOutputImitatingPromptSameChunkMarkerAfter(t *testing.T) {
	for _, fake := range []string{fakeCWD + "whoami", fakeCWD} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			h.out(prompt(), split)
			h.in("type notes.txt\r", split)
			// the imitation is the last line painted before the marker
			h.out("type notes.txt\r\nFILE_HEAD\r\nFILE_TAIL\r\n"+fake+"\r\n"+mark()+"\r\n"+fakeCWD, split)
			h.in("echo NEXT^_CMD\r", split)
			h.out("echo NEXT^_CMD\r\n"+mark()+"NEXT_CMD\r\n\r\n"+fakeCWD, split)
			h.seg.Close(h.off)
			h.want("type notes.txt", "echo NEXT^_CMD")
			h.mustContain(0, "FILE_HEAD", "FILE_TAIL", fake+"\r\n") // no boundary at the imitation
			h.mustContain(1, "NEXT_CMD")
			if h.note != 0 {
				t.Fatalf("fake %q split %v: unattributed %d", fake, split, h.note)
			}
		}
	}
}

// The prompt-shaped output line is followed by text typed ahead by the user
// for the NEXT command (Enter pressed while `type` still ran).
func TestCMDOutputImitatingPromptWithTypeAhead(t *testing.T) {
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(prompt(), split)
		h.in("type notes.txt\r", split)
		h.out("type notes.txt\r\n", split)
		h.in("echo NEXT^_CMD\r", split) // type-ahead
		h.out(mark()+"FILE_HEAD\r\n"+fakeCWD+"dir\r\n"+fakeCWD+"\r\nFILE_TAIL\r\n\r\n"+fakeCWD+"echo NEXT^_CMD\r\n", split)
		h.out(mark()+"NEXT_CMD\r\n\r\n"+fakeCWD, split)
		h.seg.Close(h.off)
		h.want("type notes.txt", "echo NEXT^_CMD")
		h.mustContain(0, "FILE_HEAD", "FILE_TAIL")
		h.mustContain(1, "NEXT_CMD")
	}
}

// Custom prompt (P marker carries its visible text).
func TestCMDOutputImitatingCustomPrompt(t *testing.T) {
	const p = "[pentest] work>"
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(markP(p)+p, split)
		h.in("type log.txt\r", split)
		h.out("type log.txt\r\n"+markP(p)+"LOG_HEAD\r\n"+p+"net user\r\n"+p+"\r\nLOG_TAIL\r\n\r\n"+p, split)
		h.in("echo NEXT^_CMD\r", split)
		h.out("echo NEXT^_CMD\r\n"+markP(p)+"NEXT_CMD\r\n\r\n"+p, split)
		h.seg.Close(h.off)
		h.want("type log.txt", "echo NEXT^_CMD")
		h.mustContain(0, "LOG_HEAD", "net user", "LOG_TAIL")
		h.mustContain(1, "NEXT_CMD")
	}
}

// Three pasted commands, all three markers before one frame (native 04A
// order); the middle command's output imitates the prompt.
func TestCMDOutputImitatingPromptInPastedBlock(t *testing.T) {
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(prompt(), split)
		h.in("echo P^_1\rtype x.txt\recho P^_3\r", split)
		h.out("echo P^_1\r\n", split)
		h.out(mark()+mark()+mark(), split)
		h.out("P_1\r\n\r\n"+fakeCWD+"type x.txt\r\nX_HEAD\r\n"+fakeCWD+"echo P^_3\r\n"+fakeCWD+"\r\nX_TAIL\r\n\r\n"+
			fakeCWD+"echo P^_3\r\nP_3\r\n\r\n"+fakeCWD, split)
		h.seg.Close(h.off)
		// the imitation "C:\Users\tester>echo P^_3" inside x.txt is the
		// documented limit (output reproducing the prompt AND the exact
		// command already typed ahead): it is not exercised here as a pass
		// condition; what must hold is that nothing is lost.
		cmds := h.commands()
		if len(cmds) != 3 || cmds[0] != "echo P^_1" || cmds[1] != "type x.txt" || cmds[2] != "echo P^_3" {
			t.Fatalf("split %v: commands %q", split, cmds)
		}
		h.mustContain(0, "P_1")
		h.mustContain(1, "X_HEAD")
		h.mustContain(2, "P_3")
	}
}

// Resize while idle at the prompt: ConPTY repaints the screen (here with a
// full clear), including the old prompt-shaped output. The finished command
// keeps its end; the next command and its output are recorded.
func TestCMDResizeRepaintKeepsBoundaries(t *testing.T) {
	for _, clear := range []bool{true, false} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			h.out(prompt(), split)
			h.in("type notes.txt\r", split)
			h.out("type notes.txt\r\n"+mark()+"FILE_HEAD\r\n"+fakeCWD+"whoami\r\nFILE_TAIL\r\n\r\n"+fakeCWD, split)
			before := h.rows[0]
			if before.EndedAt == 0 {
				t.Fatalf("clear %v split %v: command not ended at its prompt: %+v", clear, split, before)
			}
			h.seg.Resize(100, 30)
			rp := "\x1b[H"
			if clear {
				rp += "\x1b[2J"
			}
			rp += fakeCWD + "type notes.txt\x1b[K\r\nFILE_HEAD\x1b[K\r\n" + fakeCWD + "whoami\x1b[K\r\nFILE_TAIL\x1b[K\r\n\x1b[K\r\n" + fakeCWD + "\x1b[K"
			h.out(rp, split)
			if after := h.rows[0]; after.OutEndOff != before.OutEndOff || after.EndedAt != before.EndedAt {
				t.Fatalf("clear %v split %v: repaint moved the end: %+v -> %+v", clear, split, before, after)
			}
			h.in("echo NEXT^_CMD\r", split)
			h.out("echo NEXT^_CMD\r\n"+mark()+"NEXT_CMD\r\n\r\n"+fakeCWD, split)
			h.seg.Close(h.off)
			h.want("type notes.txt", "echo NEXT^_CMD")
			h.mustContain(0, "FILE_HEAD", "whoami", "FILE_TAIL")
			h.mustContain(1, "NEXT_CMD")
		}
	}
}

// Prompts that take no command (Enter on an empty line, Ctrl-C): the
// finished command keeps its end at the FIRST prompt, the marker count stays
// aligned, the next command is recorded.
func TestCMDEmptyEnterAndCtrlCKeepAlignment(t *testing.T) {
	for _, key := range []string{"\r", "abc\x03"} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			h.out(prompt(), split)
			h.in("echo ONE\r", split)
			h.out("echo ONE\r\n"+mark()+"ONE\r\n\r\n"+fakeCWD, split)
			end := h.rows[0]
			h.in(key, split)
			echo := ""
			if key != "\r" {
				echo = "abc^C"
			}
			h.out(echo+"\r\n"+mark()+"\r\n"+fakeCWD, split)
			h.in("echo TWO\r", split)
			h.out("echo TWO\r\n"+mark()+"TWO\r\n\r\n"+fakeCWD, split)
			h.seg.Close(h.off)
			h.want("echo ONE", "echo TWO")
			if r := h.rows[0]; r.OutEndOff != end.OutEndOff || r.EndedAt != end.EndedAt {
				t.Fatalf("key %q split %v: first command's end moved: %+v -> %+v", key, split, end, r)
			}
			h.mustContain(1, "TWO")
			h.mustNotContain(1, "ONE")
		}
	}
}

// Documented limit: output that reproduces the prompt AND exactly the
// command the user already typed ahead (with Enter) is taken for that
// command's prompt, so the boundary between the two commands is too early.
// Even then nothing is lost: both commands are recorded and the next
// command's output stays in its range.
func TestCMDImitationOfTypedAheadCommandLosesNothing(t *testing.T) {
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(prompt(), split)
		h.in("type notes.txt\r", split)
		h.out("type notes.txt\r\n", split)
		h.in("echo NEXT^_CMD\r", split)
		h.out(mark()+"FILE_HEAD\r\n"+fakeCWD+"echo NEXT^_CMD\r\nFILE_TAIL\r\n\r\n"+fakeCWD+"echo NEXT^_CMD\r\n", split)
		h.out(mark()+"NEXT_CMD\r\n\r\n"+fakeCWD, split)
		h.seg.Close(h.off)
		h.want("type notes.txt", "echo NEXT^_CMD")
		h.mustContain(0, "FILE_HEAD")
		h.mustContain(1, "NEXT_CMD")
	}
}

// Many prompt-like output lines (a long log of "C:\path>" lines) move the
// provisional end many times but cost one metadata write per output chunk,
// not one per line.
func TestCMDManyPromptLikeLinesCoalesceWrites(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("type huge.log\r", false)
	h.out("type huge.log\r\n", false)
	before := h.writes
	h.out(mark()+strings.Repeat(fakeCWD+"dir\r\n", 10000)+"\r\n"+fakeCWD, false)
	if w := h.writes - before; w > 2 {
		t.Fatalf("%d metadata writes for one output chunk", w)
	}
	h.in("echo NEXT^_CMD\r", false)
	h.out("echo NEXT^_CMD\r\n"+mark()+"NEXT_CMD\r\n\r\n"+fakeCWD, false)
	h.seg.Close(h.off)
	h.want("type huge.log", "echo NEXT^_CMD")
	if r := h.outOf(0); strings.Count(r, fakeCWD+"dir") != 10000 {
		t.Fatalf("the log is not wholly in its command's range: %d lines", strings.Count(r, fakeCWD+"dir"))
	}
	h.mustContain(1, "NEXT_CMD")
}
