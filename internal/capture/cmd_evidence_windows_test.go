//go:build windows

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex iteration 04A: evidence for the native CMD tests.
//
// With PENTRAIL_CMD_EVIDENCE_DIR set to a dedicated, existing folder, every
// native CMD test writes (synthetic data only; never the database key):
//
//	trace.jsonl    every call into the CMD segmenter in the order it received
//	               them (input raw+decoded, output bytes, reset, close) plus
//	               every row it wrote and every unattributed count; streamed
//	               line by line, so it survives t.Fatal, panics and timeouts
//	frames.jsonl   every Data frame the test sent and every Output chunk the
//	               client received, with client-side byte offsets and times
//	raw.bin        the stored session stream (masked; same offsets)
//	screen.bin     everything the attached client received
//	commands.json  stored commands (ranges, end_reason, times)
//	session.json   stored session row (raw bytes, unattributed count, ...)
//	result.txt     PASS/FAIL and every failure message, written BEFORE Fatal
//
// The folder is outside the test's TempDir and is never deleted by the test.
//
// Without PENTRAIL_CMD_EVIDENCE_DIR (Codex 04I: the failing full run had no
// trace) the same files are kept in memory (trace and frames capped at
// memTraceCap each) and written only if the test FAILED, to a new folder
// pentrail-cmd-fail-<test>-* in the system temp directory (outside the
// test's TempDir, never deleted by the test; its path is logged). Passing
// tests write nothing.
// `go test -run TestReplayCMDTrace` (any OS) replays trace.jsonl through the
// platform-independent segmenter: PENTRAIL_CMD_TRACE=<that test's folder>.
type cmdEvidence struct {
	dir    string // "" in memory mode until a failure is written out
	name   string
	mem    bool
	mu     sync.Mutex
	trace  io.Writer
	frames io.Writer
	files  map[string][]byte // memory mode: dump()/note() output
	order  []string
	start  time.Time
	seq    int64
	recvAt int64
	dumped bool
}

// memTraceCap bounds each in-memory stream (trace, frames).
const memTraceCap = 64 << 20

// capBuf keeps the first memTraceCap bytes, whole lines only, and counts
// what it dropped.
type capBuf struct {
	b       bytes.Buffer
	dropped int64
}

func (c *capBuf) Write(p []byte) (int, error) {
	if c.dropped > 0 || c.b.Len()+len(p) > memTraceCap {
		c.dropped += int64(len(p))
		return len(p), nil
	}
	return c.b.Write(p)
}

// newCmdEvidence is called before the test opens anything, so its Fatal
// (a misconfigured folder) leaves nothing to clean up. mem: keep a failure
// trace in memory when no evidence folder is configured.
func newCmdEvidence(t *testing.T, mem bool) *cmdEvidence {
	name := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(t.Name(), "_")
	base := os.Getenv("PENTRAIL_CMD_EVIDENCE_DIR")
	if base == "" {
		if !mem {
			return nil
		}
		return &cmdEvidence{name: name, mem: true, start: time.Now(), trace: &capBuf{}, frames: &capBuf{}, files: map[string][]byte{}}
	}
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		t.Fatalf("PENTRAIL_CMD_EVIDENCE_DIR=%q must be an existing folder", base)
	}
	dir := filepath.Join(base, name+"-"+time.Now().Format("20060102-150405.000"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &cmdEvidence{dir: dir, name: name, start: time.Now()}
	tr, err := os.OpenFile(filepath.Join(dir, "trace.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := os.OpenFile(filepath.Join(dir, "frames.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		tr.Close()
		t.Fatal(err)
	}
	e.trace, e.frames = tr, fr
	t.Logf("CMD evidence folder: %s", dir)
	return e
}

func (e *cmdEvidence) line(f io.Writer, v any) {
	b, _ := json.Marshal(v)
	f.Write(append(b, '\n')) // unbuffered: survives a crash of the test
}

// traceEvent is installed as cmdTraceHook.
func (e *cmdEvidence) traceEvent(ev SegTraceEvent) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	ev.Seq = e.seq
	ev.TNs = time.Since(e.start).Nanoseconds()
	e.line(e.trace, ev)
}

type frameEvent struct {
	TNs  int64  `json:"t_ns"`
	Dir  string `json:"dir"`           // sent (test -> session) | recv (session -> client)
	Off  int64  `json:"off,omitempty"` // recv: offset of this chunk in screen.bin
	Data []byte `json:"data"`
}

func (e *cmdEvidence) frame(dir string, b []byte) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := frameEvent{TNs: time.Since(e.start).Nanoseconds(), Dir: dir, Data: append([]byte(nil), b...)}
	if dir == "recv" {
		ev.Off = e.recvAt
		e.recvAt += int64(len(b))
	}
	e.line(e.frames, ev)
}

func (e *cmdEvidence) write(name string, b []byte) {
	if e.mem {
		e.mu.Lock()
		e.keep(name, append([]byte(nil), b...))
		e.mu.Unlock()
		return
	}
	if err := os.WriteFile(filepath.Join(e.dir, name), b, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "evidence %s: %v\n", name, err)
	}
}

func (e *cmdEvidence) note(format string, args ...any) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mem {
		e.keep("result.txt", append(e.files["result.txt"], fmt.Sprintf(format+"\n", args...)...))
		return
	}
	f, err := os.OpenFile(filepath.Join(e.dir, "result.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintf(f, format+"\n", args...)
	f.Close()
}

// dump writes the stored state. st must be a Store opened on the test's DB
// AFTER its RunServer finished (or nil to only write the screen).
func (e *cmdEvidence) dump(n *nativeCMD, st *store.Store) {
	if e == nil {
		return
	}
	e.write("screen.bin", []byte(n.text()))
	if st == nil || e.dumped {
		return
	}
	e.dumped = true
	if ss, err := st.ListSessions(); err == nil {
		js, _ := json.MarshalIndent(ss, "", "  ")
		e.write("session.json", js)
		for _, s := range ss {
			if s.ID == n.id {
				raw, missing, err := st.ReadRange(n.id, 0, s.RawBytes)
				e.write("raw.bin", raw)
				e.note("raw.bin: %d bytes, missing=%d, err=%v", len(raw), missing, err)
			}
		}
	} else {
		e.note("ListSessions: %v", err)
	}
	if cmds, err := st.ListCommands(n.id); err == nil {
		js, _ := json.MarshalIndent(cmds, "", "  ")
		e.write("commands.json", js)
	} else {
		e.note("ListCommands: %v", err)
	}
}

// close finishes the evidence after the session server ended.
func (e *cmdEvidence) close(t *testing.T, n *nativeCMD) {
	if e == nil {
		return
	}
	if !e.dumped {
		if st, err := store.Open(n.db, []byte(nativeKey)); err == nil {
			e.dump(n, st)
			st.Close()
		} else {
			e.note("reopen for evidence: %v", err)
			e.dump(n, nil)
		}
	} else {
		e.dump(n, nil) // final screen
	}
	e.note("result: failed=%v", t.Failed())
	if !e.mem {
		e.trace.(*os.File).Close()
		e.frames.(*os.File).Close()
		return
	}
	if !t.Failed() {
		return // passing test: nothing written
	}
	e.writeOut(t)
}

func (e *cmdEvidence) keep(name string, b []byte) {
	if _, ok := e.files[name]; !ok {
		e.order = append(e.order, name)
	}
	e.files[name] = b
}

// writeOut (memory mode, failed test): every kept file into a new folder in
// the system temp directory, outside the test's TempDir.
func (e *cmdEvidence) writeOut(t *testing.T) {
	e.mu.Lock()
	defer e.mu.Unlock()
	dir, err := os.MkdirTemp("", "pentrail-cmd-fail-"+e.name+"-")
	if err != nil {
		t.Logf("CMD failure trace NOT written: %v", err)
		return
	}
	tr, fr := e.trace.(*capBuf), e.frames.(*capBuf)
	put := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Logf("CMD failure trace %s: %v", name, err)
		}
	}
	put("trace.jsonl", tr.b.Bytes())
	put("frames.jsonl", fr.b.Bytes())
	for _, name := range e.order {
		b := e.files[name]
		if name == "result.txt" && (tr.dropped > 0 || fr.dropped > 0) {
			b = append(b, fmt.Sprintf("memory trace truncated: trace dropped %d B, frames dropped %d B\n", tr.dropped, fr.dropped)...)
		}
		put(name, b)
	}
	t.Logf("CMD failure trace written to %s (replay: PENTRAIL_CMD_TRACE=<that folder> go test -run TestReplayCMDTrace)", dir)
}

// fatalf records the failure in the evidence folder BEFORE failing.
func (n *nativeCMD) fatalf(format string, args ...any) {
	n.t.Helper()
	msg := fmt.Sprintf(format, args...)
	if n.ev != nil {
		n.ev.dump(n, nil)
		n.ev.note("FAIL: %s", strings.TrimSpace(msg))
	}
	n.t.Fatal(msg)
}
