//go:build windows

package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
)

// Codex 04C, native counterparts of the unit tests in vtscreen_bound_test.go
// and cmd_imitation_test.go. Synthetic data in this test's own TempDir only.

func (n *nativeCMD) waitPromptsFor(k int, d time.Duration) {
	n.t.Helper()
	until := time.Now().Add(d)
	for time.Now().Before(until) {
		if n.prompts() >= k {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	n.fatalf("waiting %v for %d prompts; screen tail %q", d, k, tail(n.text(), 400))
}

func (n *nativeCMD) resize(cols, rows uint16) {
	n.t.Helper()
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], rows)
	binary.BigEndian.PutUint16(b[2:], cols)
	n.ev.frame("sent", append([]byte("resize:"), b...))
	if err := n.w.Send(sessionio.Resize, b); err != nil {
		n.t.Fatal(err)
	}
}

// heapNow: heap in use after a full GC.
func heapNow() int64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// clientState: client counters (04D diagnostics).
func (n *nativeCMD) clientState() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	end := n.readEnd
	if end == "" {
		end = "reading"
	}
	return fmt.Sprintf("client_bytes=%d markers=%d last_recv=%v ago read_loop=%s", n.recvBytes, n.markers, since(n.lastRecv), end)
}

// waitProgress waits for k prompt markers while the output path makes
// progress. It fails when neither the PTY side nor the client received
// anything for stall, or after limit; every 10 s it logs the counters.
func (n *nativeCMD) waitProgress(k int, fs *flowStats, cs *commitStats, stall, limit time.Duration) {
	n.t.Helper()
	start := time.Now()
	lastLog := start
	var lastClient, lastPTY int64 = -1, -1
	lastMove := start
	for n.prompts() < k {
		n.mu.Lock()
		cb := n.recvBytes
		n.mu.Unlock()
		fs.mu.Lock()
		pb := fs.bytes
		fs.mu.Unlock()
		if cb != lastClient || pb != lastPTY {
			lastClient, lastPTY, lastMove = cb, pb, time.Now()
		}
		if time.Since(lastLog) >= 10*time.Second {
			lastLog = time.Now()
			n.t.Logf("FLOW progress %s; %s; %s", n.clientState(), fs.summary(), cs.summary())
		}
		if time.Since(lastMove) > stall || time.Since(start) > limit {
			n.ev.note("FLOW at failure: %s; %s; %s", n.clientState(), fs.summary(), cs.summary())
			n.fatalf("waiting for %d prompts: no progress for %v or over %v (waited %v); %s; %s; screen tail %q",
				k, stall, limit, time.Since(start).Round(time.Second), n.clientState(), fs.summary(), tail(n.text(), 300))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A file of N MiB without a single LF (PENTRAIL_BIG_MIB, default 8) is typed
// out, then an ordinary command follows. 04D: the output path is measured
// per stage (PTY read, CMD observer, OSC parser, durable store, client hub)
// together with the client's byte and marker counters; waiting fails on a
// STALL (no bytes moving for 2 min) or after 30 min, and the time taken is
// reported, not hidden. Run it without PENTRAIL_CMD_EVIDENCE_DIR for timing
// (the evidence trace copies every output chunk under the capture lock).
func TestNativeCMDLongOutputWithoutLF(t *testing.T) {
	mib := 8
	if s := os.Getenv("PENTRAIL_BIG_MIB"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			mib = v
		}
	}
	dir := t.TempDir()
	big := filepath.Join(dir, "big.txt")
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789" // no secret pattern can match
	content := make([]byte, mib<<20)
	for i := range content {
		content[i] = abc[(i*7+i/97)%len(abc)]
	}
	if err := os.WriteFile(big, content, 0o600); err != nil {
		t.Fatal(err)
	}
	fs := installFlow(t)
	cs := installCommitStats(t) // 04E: sub-stages of every durable write
	probe := startSchedProbe(t) // 04J: independent stall detector
	diag := startLatencyDiag(t) // 04K: execution trace etc., only with PENTRAIL_LATENCY_DIAG
	n := startNativeCMDUntraced(t)
	base := heapNow()
	p := n.prompts()
	t0 := time.Now()
	n.typeFrames(`type "` + big + "\"\r")
	n.waitProgress(p+1, fs, cs, 2*time.Minute, 30*time.Minute)
	typed := time.Since(t0)
	t.Logf("FLOW big output done in %v: %s; %s; %s", typed.Round(time.Millisecond), n.clientState(), fs.summary(), cs.summary())
	rows, cursorLed := rowShapes([]byte(n.text()))
	t.Logf("FLOW output shape: %d lines, %d start with a cursor-positioning sequence", rows, cursorLed)
	time.Sleep(500 * time.Millisecond) // the frame with the prompt
	n.mu.Lock()
	clientBytes, clientCap := int64(n.screen.Len()), int64(n.screen.Cap())
	n.mu.Unlock()
	grown := heapNow() - base - clientCap // the test's own copy of the screen is not the server's
	// next command after the full output was received
	p = n.prompts()
	t1 := time.Now()
	n.typeFrames("echo AFTER^_BIG\r")
	n.waitProgress(p+1, fs, cs, time.Minute, 5*time.Minute)
	latency := time.Since(t1)
	n.typeFrames("exit\r")
	re, sess, cmds, raw := n.finish()
	t.Logf("NATIVE_CMD_BIG %d MiB file: typed out in %v (%.2f MiB/s), client received %d bytes, server heap retained %+.1f MiB, next command's prompt after %v",
		mib, typed.Round(time.Millisecond), float64(mib)/typed.Seconds(), clientBytes, float64(grown)/(1<<20), latency.Round(time.Millisecond))
	n.ev.note("FLOW final: %s; %s; %s", n.clientState(), fs.summary(), cs.summary())
	// 04E acceptance: no write costs hundreds of ms. 04J: checked as the
	// algorithmic cost of this run's own batches (replayed after the
	// session) plus every live overrun explained by a scheduler stall in
	// its window (latency_probe_test.go); otherwise FAIL.
	cs.mu.Lock()
	worstStep, worstCommit := cs.max[0], cs.max[5]
	cs.mu.Unlock()
	latFail, latReport := checkLatency(t, []byte(n.text()), fs, cs, probe, diag)
	t.Log(latReport)
	n.ev.note("%s", latReport)
	if typed > 2*time.Minute || latFail {
		n.fatalf("too slow: %d MiB took %v; worst redaction step %v, worst commit %v; %s; %s", mib, typed, worstStep, worstCommit, latReport, cs.summary())
	}
	if grown > 64<<20 {
		n.fatalf("server heap grew by %.1f MiB for a %d MiB line", float64(grown)/(1<<20), mib)
	}
	submitted := []string{`type "` + big + `"`, "echo AFTER^_BIG", "exit"}
	checkCommon(n, re, n.id, sess, cmds, submitted, raw)
	if len(cmds) < 2 || cmds[0].Command != submitted[0] || cmds[1].Command != submitted[1] {
		n.fatalf("commands %+v", cmds)
	}
	outputIn(n, re, n.id, cmds, "echo AFTER^_BIG", "AFTER_BIG")
	if c := cmds[0]; c.OutEndOff-c.OutStartOff < 1<<20 {
		n.fatalf("the big output is not in its command's range: %+v", c)
	}
	// whole raw stream after reopen against what the client received: the
	// only allowed differences are the length-preserving masking of marker
	// payloads and the documented fail-closed masking of lines longer than
	// redact.MaxLine (rawMatchesClient)
	if int64(len(raw)) != sess.RawBytes {
		n.fatalf("raw %d bytes, session says %d", len(raw), sess.RawBytes)
	}
	masked, err := rawMatchesClient([]byte(raw), []byte(n.text()))
	if err != nil {
		n.fatalf("%v", err)
	}
	t.Logf("NATIVE_CMD_BIG raw_bytes=%d client_bytes=%d masked_fail_closed=%d commands=%d", sess.RawBytes, clientBytes, masked, len(cmds))
}

// segLog collects, in memory, the segmenter's decisions and the resize/
// write/note events of THIS test's session (04D). It is installed only
// when no evidence folder is used (that one records everything) and is
// printed when the test fails.
type segLog struct {
	mu    sync.Mutex
	lines []string
}

func installSegLog(t *testing.T) *segLog {
	if os.Getenv("PENTRAIL_CMD_EVIDENCE_DIR") != "" {
		return nil
	}
	l := &segLog{}
	cmdTraceHook = func(ev SegTraceEvent) {
		var line string
		switch ev.Ev {
		case "seg":
			line = "seg " + ev.Note
		case "resize":
			line = fmt.Sprintf("resize %dx%d", ev.Cols, ev.Rows)
		case "write":
			line = fmt.Sprintf("write idx=%d %q out=%d..%d ended=%v", ev.Cmd.Index, ev.Cmd.Command, ev.Cmd.OutStartOff, ev.Cmd.OutEndOff, ev.Cmd.EndedAt != 0)
		case "note":
			line = fmt.Sprintf("unattributed +%d", ev.N)
		case "input":
			line = fmt.Sprintf("input %q", ev.Dec)
		default:
			return
		}
		l.mu.Lock()
		l.lines = append(l.lines, line)
		l.mu.Unlock()
	}
	t.Cleanup(func() {
		cmdTraceHook = nil
		if t.Failed() {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, x := range l.lines {
				t.Log("SEGLOG " + x)
			}
		}
	})
	return l
}

// renderedTail: the last k lines of the rendered client screen (explicit
// terminal mapping, vtTestScreen), for failure messages.
func renderedTail(screen string, k int) string {
	s := newVTTestScreen(cmdCols, cmdRows)
	s.Feed([]byte(screen), 0, 0)
	tr := s.transcript()
	if len(tr) > k {
		tr = tr[len(tr)-k:]
	}
	return strings.Join(tr, "\n")
}

// A file whose lines look exactly like this shell's prompt is typed out;
// then an ordinary command; then a resize (ConPTY repaints the screen with
// the prompt-like lines on it) and one more command.
func TestNativeCMDOutputImitatingPrompt(t *testing.T) {
	dir := t.TempDir()
	installSegLog(t) // before the session starts: the observer is created with it
	n := startNativeCMD(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("RENDERED client screen (last 40 lines; resize uses the current size only):\n%s", renderedTail(n.text(), 40))
		}
	})
	p := n.prompts()
	n.typeFrames(`cd /d "` + dir + "\"\r")
	n.waitPrompts(p + 1)
	fake := dir + ">"
	body := "FAKE_HEAD\r\n" + fake + "whoami\r\n" + fake + "\r\n" + fake + "net user\r\nFAKE_TAIL\r\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, cmd := range []string{"type fake.txt", "echo NEXT^_CMD"} {
		p = n.prompts()
		n.typeFrames(cmd + "\r")
		n.waitFor([]string{"FAKE_TAIL", "NEXT_CMD"}[i])
		n.waitPrompts(p + 1)
	}
	time.Sleep(300 * time.Millisecond)
	n.resize(100, 30)
	time.Sleep(time.Second)
	n.resize(120, 30)
	time.Sleep(time.Second)
	p = n.prompts()
	n.typeFrames("echo AFTER^_RESIZE\r")
	n.waitFor("AFTER_RESIZE")
	n.waitPrompts(p + 1)
	n.typeFrames("exit\r")
	re, sess, cmds, raw := n.finish()
	submitted := []string{`cd /d "` + dir + `"`, "type fake.txt", "echo NEXT^_CMD", "echo AFTER^_RESIZE", "exit"}
	checkCommon(n, re, n.id, sess, cmds, submitted, raw)
	if len(cmds) < 4 {
		n.fatalf("commands %+v", cmds)
	}
	for i, want := range submitted[:4] {
		if cmds[i].Command != want {
			n.fatalf("command %d is %q, want %q: %+v", i, cmds[i].Command, want, cmds)
		}
	}
	tf := outputIn(n, re, n.id, cmds, "type fake.txt", "FAKE_HEAD")
	data, _, _ := re.ReadRange(n.id, tf.OutStartOff, tf.OutEndOff)
	for _, tok := range []string{"whoami", "net user", "FAKE_TAIL"} {
		if !bytes.Contains(data, []byte(tok)) {
			n.fatalf("false boundary: %q of the file is not in the type command's range: %q", tok, data)
		}
	}
	outputIn(n, re, n.id, cmds, "echo NEXT^_CMD", "NEXT_CMD")
	outputIn(n, re, n.id, cmds, "echo AFTER^_RESIZE", "AFTER_RESIZE")
	want := int64(0)
	if cmds[len(cmds)-1].Command != "exit" {
		want = 1 // cmd exited before painting the echo of `exit`
	}
	if sess.Unattributed != want {
		n.fatalf("unattributed %d, want %d", sess.Unattributed, want)
	}
	t.Logf("NATIVE_CMD_IMITATION commands=%d type_range=%d..%d unattributed=%d", len(cmds), tf.OutStartOff, tf.OutEndOff, sess.Unattributed)
}
