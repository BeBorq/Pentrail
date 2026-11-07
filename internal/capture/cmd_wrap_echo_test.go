package capture

import (
	"strings"
	"testing"
)

// Codex 04I (TestNativeCMDOffOn: `echo REC^_ONE` executed, visible, not
// recorded — no trace of that failure exists, so this is a HYPOTHESIS, not a
// proven cause): with the native tests' long prompt (~119 columns) every
// echo wraps at column 120. Painted in one go the continuation comes by
// autowrap; but when the echo is painted across frames, ConPTY can continue
// it on the next row after an explicit cursor position or CRLF, i.e. at
// column 0, which the screen model takes for a new logical line: the
// prompt line then shows only "...>e" and the typed command is not
// confirmed. The continuation is now joined — only when the typed input
// confirms the joined text — so an output line that merely follows a full
// prompt line is never merged.

func longPrompt() (marker, text string) {
	text = `C:\` + strings.Repeat("p", 115) + ">" // 119 columns
	return "\x1b]697;" + segTok + ";A\x07", text
}

func TestCMDWrappedEchoContinuedAtColumnZero(t *testing.T) {
	mk, pt := longPrompt()
	for _, cont := range []string{"\x1b[2;1H", "\r\n", "\x1b[?25l\x1b[2;1H"} {
		for _, split := range []bool{false, true} {
			h := newSeg(t)
			h.out(mk+pt, split)
			h.in("echo REC^_ONE\r", split)
			h.out("e", split)                 // first frame: up to the last column
			h.out(cont+"cho REC^_ONE", split) // next frame: the rest at column 0
			h.out(mk+"\r\nREC_ONE\r\n\r\n"+pt, split)
			h.in("exit\r", split)
			h.out("exit\r\n", split)
			h.seg.Close(h.off)
			h.want("echo REC^_ONE", "exit")
			h.mustContain(0, "REC_ONE")
			if h.note != 0 {
				t.Fatalf("cont %q split %v: unattributed %d", cont, split, h.note)
			}
		}
	}
}

// Painted in one go (autowrap) it was already right; it stays right.
func TestCMDWrappedEchoByAutowrap(t *testing.T) {
	mk, pt := longPrompt()
	h := newSeg(t)
	h.out(mk+pt, false)
	h.in("echo REC^_ONE\r", false)
	h.out("echo REC^_ONE\r\n"+mk+"REC_ONE\r\n\r\n"+pt, false)
	h.seg.Close(h.off)
	h.want("echo REC^_ONE")
	h.mustContain(0, "REC_ONE")
}

// A prompt line filled exactly to the last column by the echo, followed by
// the command's output on the next row: confirmed without any join, and the
// output is not merged into the command.
func TestCMDFullPromptLineThenOutputIsNotJoined(t *testing.T) {
	mk, pt := longPrompt()
	h := newSeg(t)
	h.out(mk+pt, false)
	h.in("x\r", false) // prompt (119) + "x" = exactly 120 columns
	h.out("x\r\n"+mk+"'x' is not recognized\r\n\r\n"+pt, false)
	h.seg.Close(h.off)
	h.want("x")
	h.mustContain(0, "is not recognized")
}

// The joined text must match what was typed: an unrelated line after a
// full, unconfirmed prompt line does not create a command.
func TestCMDWrapJoinNeedsTypedEvidence(t *testing.T) {
	mk, pt := longPrompt()
	h := newSeg(t)
	h.out(mk+pt, false)
	h.in("echo A\r", false)
	h.out("Z", false)              // something else fills the last column
	h.out("\x1b[2;1Hcho A", false) // and a line at column 0
	h.out(mk+"\r\nA\r\n\r\n"+pt, false)
	h.seg.Close(h.off)
	if len(h.rows) != 0 {
		t.Fatalf("a command was made from text the user did not type: %v", h.commands())
	}
}

// The native TestNativeCMDOffOn sequence with the 119-column prompt of the
// failing run: REC_ONE's echo painted across frames (continued at column 0),
// then off, a paused command, on, REC_TWO, exit. Before 04I the result was
// exactly the failure's metadata: only REC_TWO and exit.
func TestCMDOffOnWithWrappedFirstEcho(t *testing.T) {
	mk, pt := longPrompt()
	for _, split := range []bool{false, true} {
		h := newSeg(t)
		h.out(mk+pt, split)
		h.in("echo REC^_ONE\r", split)
		h.out("e", split)
		h.out("\x1b[2;1Hcho REC^_ONE", split)
		h.out(mk+"\r\nREC_ONE\r\n\r\n"+pt, split)
		h.seg.Reset(h.off) // off
		h.rec = false
		h.in("echo PRIV^_ATE\r", split)
		h.out("echo PRIV^_ATE\r\n"+mk+"PRIV_ATE\r\n\r\n"+pt, split)
		h.rec = true
		h.seg.Reset(h.off) // on
		h.in("echo REC^_TWO\r", split)
		h.out("echo REC^_TWO\r\n"+mk+"REC_TWO\r\n\r\n"+pt, split)
		h.in("exit\r", split)
		h.out("exit\r\n", split)
		h.seg.Close(h.off)
		h.want("echo REC^_ONE", "echo REC^_TWO", "exit")
		h.mustContain(0, "REC_ONE")
		h.mustContain(1, "REC_TWO")
		if strings.Contains(h.stream.String(), "PRIV") {
			t.Fatal("paused output recorded")
		}
	}
}
