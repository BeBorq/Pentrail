package capture

import (
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Codex 04C, finding 1: one output line without LF (base64, minified JSON,
// binary text) of any size must not grow the screen model. Before 04C the
// logical line kept every row it autowrapped into (measured: 21.5 MiB heap
// per MiB of output, and quadratic CPU while the line could still become a
// "X:\path>" prompt: 4 MiB took 125 s).

func b64Chunk(n int) []byte {
	const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = abc[(i*7+i/64)%64]
	}
	return b
}

type longLineRun struct {
	elapsed, worst time.Duration
	heapGrowth     int64 // retained after GC, bytes
	rows           int   // rows the line under the cursor holds
	head           int   // bytes of its kept head
	cut            bool
}

// feedLongLine: a command is running (or, with undecided, a prompt marker is
// pending and the line starts like "C:\"), then mib MiB without LF arrive in
// 4 KiB chunks.
func feedLongLine(t *testing.T, h *segHarness, mib int, undecided bool) longLineRun {
	t.Helper()
	h.out(prompt(), false)
	h.in("type big.b64\r", false)
	pre := "type big.b64\r\n"
	if undecided {
		pre += mark() + "\r\nC:\\"
	}
	h.out(pre, false)
	chunk := b64Chunk(4096)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	var r longLineRun
	start := time.Now()
	for fed := 0; fed < mib<<20; fed += len(chunk) {
		t0 := time.Now()
		h.seg.Output(chunk, h.off, true) // not kept in h.stream: only the model is measured
		h.off += int64(len(chunk))
		if d := time.Since(t0); d > r.worst {
			r.worst = d
		}
	}
	r.elapsed = time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	r.heapGrowth = int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if l := h.seg.cur; l != nil {
		r.rows, r.head, r.cut = len(l.rows), len(l.head), l.cut
	}
	runtime.KeepAlive(h)
	return r
}

func TestVTLongLineWithoutLFIsBounded(t *testing.T) {
	sizes := []int{1, 8, 32}
	if s := os.Getenv("PENTRAIL_VT_MIB"); s != "" { // e.g. 128 for a manual run
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			sizes = append(sizes, n)
		}
	}
	for _, undecided := range []bool{false, true} {
		for _, mib := range sizes {
			if undecided && mib > 8 {
				continue // the CPU case is shown at 1 and 8 MiB
			}
			h := newSeg(t)
			r := feedLongLine(t, h, mib, undecided)
			t.Logf("VT_BOUND undecided=%v %d MiB: %v total, worst 4KiB chunk %v, heap retained %+.2f MiB, line rows %d head %d cut %v",
				undecided, mib, r.elapsed.Round(time.Millisecond), r.worst.Round(time.Microsecond),
				float64(r.heapGrowth)/(1<<20), r.rows, r.head, r.cut)
			// strict structural bounds
			if r.rows > cmdRows {
				t.Fatalf("line holds %d rows, screen has %d", r.rows, cmdRows)
			}
			if r.head > maxLineText {
				t.Fatalf("head %d bytes > %d", r.head, maxLineText)
			}
			if !r.cut {
				t.Fatalf("a %d MiB line must be marked cut", mib)
			}
			// what the model may retain: a screen of cells plus one head
			if r.heapGrowth > 2<<20 {
				t.Fatalf("%d MiB without LF retained %.1f MiB", mib, float64(r.heapGrowth)/(1<<20))
			}
			if r.worst > 250*time.Millisecond {
				t.Fatalf("a 4 KiB chunk took %v", r.worst)
			}
		}
	}
}

// After the long line the session goes on normally: the running command is
// closed by the next prompt with its full range, the next command and its
// output are recorded.
func TestVTLongLineThenNextCommand(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	h.in("type big.b64\r", false)
	h.out("type big.b64\r\n", false)
	big := b64Chunk(3 << 20)
	h.out(string(big), false)
	h.out("\r\n"+mark()+"\r\n"+fakeCWD, false)
	h.in("echo AFTER^_BIG\r", false)
	h.out("echo AFTER^_BIG\r\n"+mark()+"AFTER_BIG\r\n\r\n"+fakeCWD, false)
	h.seg.Close(h.off)
	h.want("type big.b64", "echo AFTER^_BIG")
	if got := h.outOf(0); len(got) < len(big) || got[2:2+len(big)] != string(big) {
		t.Fatalf("the big output is not wholly in its command's range (%d bytes)", len(got))
	}
	h.mustContain(1, "AFTER_BIG")
	for _, c := range h.rows {
		if c.ExitCode != -1 || c.Complete || c.EndedAt == 0 {
			t.Fatalf("metadata %+v", c)
		}
	}
}

// A command typed on a prompt line longer than the kept text is never taken
// from a cut echo (it could be incomplete); its typed line stays unattributed.
func TestVTCutLineIsNeverACommand(t *testing.T) {
	h := newSeg(t)
	h.out(prompt(), false)
	long := "echo " + string(b64Chunk(maxLineText+cmdCols*cmdRows+100)) // longer than head + screen
	h.in(long+"\r", false)                                              // > maxLineBytes: a "bad" (unverifiable) typed line
	h.out(long+"\r\n"+mark()+"X\r\n\r\n"+fakeCWD, false)
	h.seg.Close(h.off)
	if len(h.rows) != 0 {
		t.Fatalf("a cut echo was recorded as a command: %d rows", len(h.rows))
	}
	if h.note != 1 {
		t.Fatalf("unattributed %d, want 1", h.note)
	}
}
