//go:build linux

package capture

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex 04E acceptance: a crash loses nothing the client was shown. A session
// server (this test binary, built from the current source) records an
// endless output; the test's client reads until it has N bytes and then the
// server process is killed with SIGKILL — no flush, no cleanup. After the
// database is reopened (crash recovery), every byte the client received must
// be stored, exactly as the redactor stores it (expectedStored). Meaningful
// only in the encrypted build (durable before display); synthetic data.

func TestCrashShownSessionHelper(t *testing.T) {
	db, sock := os.Getenv("PENTRAIL_CRASH_DB"), os.Getenv("PENTRAIL_CRASH_SOCK")
	if db == "" {
		t.Skip("helper process for TestCrashLosesNothingShown")
	}
	t0 := time.Now()
	st, err := store.Open(db, []byte("synthetic-crash-key"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: store open:", err)
		os.Exit(3)
	}
	id, err := st.StartSession("sh", "crash", "test")
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: start session:", err)
		os.Exit(3)
	}
	fmt.Fprintf(os.Stderr, "helper: store open + session %v\n", time.Since(t0).Round(time.Millisecond))
	// Nothing is printed before the client says "go" (the client is attached
	// by then, so it sees the stream from offset 0). Then rows with CRLF,
	// a line in progress at any moment (it is in the recovery checkpoint at
	// the kill), and ConPTY-like cursor-led rows.
	script := `read go; i=0; while :; do printf 'row %06d abcdefghijklmnopqrstuvwxyz\r\n\033[30;1Hpartial %06d ' $i $i; printf 'end\r\n'; i=$((i+1)); done`
	err = RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", script}, Store: st, SessionID: id}, sock)
	fmt.Fprintln(os.Stderr, "helper: session server returned:", err)
	os.Exit(0)
}

// syncBuffer: the helper's stderr, written by exec's copier, read by the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestCrashLosesNothingShown(t *testing.T) {
	if !store.Encrypted() {
		t.Skip("display-after-durable-write holds for the encrypted (production) build")
	}
	for _, kill := range []int{64 << 10, 300 << 10, 1 << 20} {
		crashOnce(t, kill)
	}
}

func crashOnce(t *testing.T, kill int) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pt-crash-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, sock := filepath.Join(dir, "evidence.db"), filepath.Join(dir, "s.sock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashShownSessionHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PENTRAIL_CRASH_DB="+db, "PENTRAIL_CRASH_SOCK="+sock, "GORACE=atexit_sleep_ms=0")
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// this test's own helper is always reaped, also after t.Fatal
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			cmd.Process.Kill()
			<-exited
		}
	})
	// Startup (SQLCipher key derivation, schema) can take long on a slow
	// machine: wait while the helper is alive; if it exits, say why.
	var c net.Conn
	for c == nil {
		select {
		case <-exited:
			t.Fatalf("kill at %d: helper exited before its socket appeared after %v: %v; stderr: %q", kill, time.Since(start).Round(time.Millisecond), waitErr, stderr.String())
		default:
		}
		if conn, err := net.Dial("unix", sock); err == nil {
			c = conn
			break
		}
		if time.Since(start) > 10*time.Minute {
			t.Fatalf("kill at %d: helper alive but no socket after %v; stderr: %q", kill, time.Since(start).Round(time.Second), stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer c.Close()
	ready := time.Since(start)
	w := sessionio.NewWriter(c)
	if err := w.Send(sessionio.Hello, []byte(sessionio.Version)); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := sessionio.Read(c); err != nil || typ != sessionio.Hello {
		t.Fatalf("hello %d %v; stderr %q", typ, err, stderr.String())
	}
	if err := w.Send(sessionio.Data, []byte("go\n")); err != nil {
		t.Fatal(err)
	}
	var shown bytes.Buffer
	killed := false
	for {
		typ, p, err := sessionio.Read(c)
		if err != nil {
			break // the server is gone: everything delivered has been read
		}
		if typ == sessionio.Output {
			shown.Write(p)
		}
		if !killed && shown.Len() >= kill {
			cmd.Process.Signal(syscall.SIGKILL)
			killed = true
		}
	}
	<-exited // reaped; the shell ends with its PTY (SIGHUP when the master closes)
	if !killed {
		t.Fatalf("kill at %d: the session ended by itself after %d bytes: %v; stderr %q", kill, shown.Len(), waitErr, stderr.String())
	}
	re, err := store.Open(db, []byte("synthetic-crash-key"))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := re.ListSessions()
	if err != nil || len(ss) != 1 {
		re.Close()
		t.Fatalf("sessions %v %v", ss, err)
	}
	raw, missing, err := re.ReadRange(ss[0].ID, 0, ss[0].RawBytes)
	re.Close()
	if err != nil || missing != 0 {
		t.Fatalf("raw: missing %d err %v", missing, err)
	}
	if len(raw) < shown.Len() {
		t.Fatalf("kill at %d: client was shown %d bytes, only %d stored after recovery", kill, shown.Len(), len(raw))
	}
	exp, _ := expectedStored(shown.Bytes())
	if i := firstDiff(raw[:shown.Len()], exp); i >= 0 {
		t.Fatalf("kill at %d: stored byte %d differs from what was shown: stored %q expected %q", kill, i,
			raw[max(0, i-20):min(len(exp), i+20)], exp[max(0, i-20):min(len(exp), i+20)])
	}
	t.Logf("CRASH kill after %d B: helper ready after %v; shown %d B, stored after recovery %d B (recoveries %d), every shown byte stored; helper said %q",
		kill, ready.Round(time.Millisecond), shown.Len(), len(raw), ss[0].Recoveries, strings.TrimSpace(stderr.String()))
}

func firstDiff(a, b []byte) int {
	for i := range b {
		if i >= len(a) || a[i] != b[i] {
			return i
		}
	}
	return -1
}
