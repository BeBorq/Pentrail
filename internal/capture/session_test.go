//go:build linux

package capture

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

func TestPauseResumeKeepsShellAndExcludesPrivateOutput(t *testing.T) {
	st, id, db, sock := sessionStore(t)
	done := make(chan error, 1)
	go func() {
		done <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "read a; printf BEFORE; read b; printf PRIVATE_OUTPUT; read c; printf AFTER"}, Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	if typ, _, err := sessionio.Read(c); err != nil || typ != sessionio.Hello {
		t.Fatal(typ, err)
	}
	w := sessionio.NewWriter(c)
	wait := func(marker string) {
		t.Helper()
		var b bytes.Buffer
		for {
			typ, p, err := sessionio.Read(c)
			if err != nil {
				t.Fatal(err)
			}
			if typ != sessionio.Output {
				t.Fatal("expected output")
			}
			b.Write(p)
			if strings.Contains(b.String(), marker) {
				return
			}
		}
	}
	if err := w.Send(sessionio.Data, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	wait("BEFORE")
	if state, err := sessionio.RequestControl(sock, "off"); err != nil || state.Recording {
		t.Fatal(state, err)
	}
	if err := w.Send(sessionio.Data, []byte("private-input\n")); err != nil {
		t.Fatal(err)
	}
	wait("PRIVATE_OUTPUT")
	if state, err := sessionio.RequestControl(sock, "on"); err != nil || !state.Recording {
		t.Fatal(state, err)
	}
	if err := w.Send(sessionio.Data, []byte("third\n")); err != nil {
		t.Fatal(err)
	}
	for {
		typ, p, err := sessionio.Read(c)
		if err != nil {
			t.Fatal(err)
		}
		if typ == sessionio.Finished {
			var r sessionio.Result
			if err = json.Unmarshal(p, &r); err != nil || r.Err() != nil {
				t.Fatal(r, err)
			}
			break
		}
	}
	if err := awaitServer(t, done); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ss, err := reopened.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	raw, missing, err := reopened.ReadRange(id, 0, ss[0].RawBytes)
	if err != nil || missing != 0 {
		t.Fatal(missing, err)
	}
	if !bytes.Contains(raw, []byte("BEFORE")) || !bytes.Contains(raw, []byte("AFTER")) || bytes.Contains(raw, []byte("PRIVATE_OUTPUT")) || bytes.Contains(raw, []byte("private-input")) {
		t.Fatalf("invalid recording boundaries: %q", raw)
	}
	var n int
	if err := reopened.DB().QueryRow("SELECT count(*) FROM capture_events WHERE session_id=?", id).Scan(&n); err != nil || n != 3 {
		t.Fatal("missing recording transitions", n, err)
	}
}

func sessionStore(t *testing.T) (*store.Store, int64, string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pt-session-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db := filepath.Join(dir, "evidence.db")
	st, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.StartSession("sh", "test", "test")
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	return st, id, db, filepath.Join(dir, "s.sock")
}
func sessionConnect(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			c.SetDeadline(time.Now().Add(20 * time.Second))
			if err := sessionio.NewWriter(c).Send(sessionio.Hello, []byte(sessionio.Version)); err != nil {
				c.Close()
				t.Fatal(err)
			}
			return c
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func awaitServer(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("server did not finish")
		return nil
	}
}

func TestSessionFinalResultAfterDatabaseClosed(t *testing.T) {
	st, id, db, sock := sessionStore(t)
	finished := make(chan error, 1)
	go func() {
		finished <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "sleep 0.2; printf evidence; exit 7"}, Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	var output bytes.Buffer
	err := sessionio.Receive(c, &output)
	if err == nil || !strings.Contains(err.Error(), "status 7") {
		t.Fatalf("shell result: %v", err)
	}
	if output.String() != "evidence" {
		t.Fatal(output.String())
	}
	if err := st.DB().Ping(); err == nil {
		t.Fatal("client got result before database closed")
	}
	if err := awaitServer(t, finished); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b, missing, err := reopened.ReadRange(id, 0, 8)
	if err != nil || missing != 0 || string(b) != "evidence" {
		t.Fatalf("persisted evidence: %q missing=%d err=%v", b, missing, err)
	}
}

func TestSessionReportsFinalPersistenceFailure(t *testing.T) {
	st, id, _, sock := sessionStore(t)
	if _, err := st.DB().Exec("DROP TABLE raw_chunks"); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		finished <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "sleep 0.2; printf evidence"}, Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	err := sessionio.Receive(c, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Fatalf("client silently accepted capture failure: %v", err)
	}
	if err := awaitServer(t, finished); err == nil {
		t.Fatal("server lost persistence error")
	}
}

func TestSessionContinuesAfterClientDisconnect(t *testing.T) {
	st, id, db, sock := sessionStore(t)
	finished := make(chan error, 1)
	go func() {
		finished <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "sleep 0.3; printf after_disconnect"}, Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	if typ, _, err := sessionio.Read(c); err != nil || typ != sessionio.Hello {
		c.Close()
		t.Fatalf("handshake: %v", err)
	}
	c.Close()
	if err := awaitServer(t, finished); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(db, []byte("session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b, missing, err := reopened.ReadRange(id, 0, int64(len("after_disconnect")))
	if err != nil || missing != 0 || string(b) != "after_disconnect" {
		t.Fatalf("capture after disconnect: %q missing=%d err=%v", b, missing, err)
	}
}

// Codex review: a definitive storage failure (not a transient lock) used to
// kill the shell — and with it the user's running work. Now the shell keeps
// running unrecorded, the terminal shows why, `status` reports it, input
// still reaches the shell, and the final result is INCOMPLETE.
func TestStorageFailureKeepsShellAlive(t *testing.T) {
	st, id, _, sock := sessionStore(t)
	if _, err := st.DB().Exec("DROP TABLE raw_chunks"); err != nil { // non-lock failure
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		finished <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c",
			"printf 'first\\n'; sleep 0.3; printf 'second\\n'; read line; printf 'got:%s\\n' \"$line\""},
			Store: st, SessionID: id}, sock)
	}()
	c := sessionConnect(t, sock)
	defer c.Close()
	var screen lockedBuffer
	result := make(chan error, 1)
	pr, pw := net.Pipe()
	go func() { result <- sessionio.Receive(c, pw); pw.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := pr.Read(buf)
			screen.Write(buf[:n])
			if e != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(screen.String(), "second") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(screen.String(), "STOPPED") {
		t.Fatalf("no visible notice on the terminal: %q", screen.String())
	}
	state, err := sessionio.RequestControl(sock, "status")
	if err != nil || state.Recording || state.CaptureError == "" {
		t.Fatalf("status must report the stopped recording: %+v %v", state, err)
	}
	if _, err := sessionio.RequestControl(sock, "on"); err == nil {
		t.Fatal("`on` claimed to resume recording after a storage failure")
	}
	// the shell is alive and still receives the user's input
	if err := sessionio.NewWriter(c).Send(sessionio.Data, []byte("still-here\n")); err != nil {
		t.Fatal(err)
	}
	var rerr error
	select {
	case rerr = <-result:
	case <-time.After(15 * time.Second):
		t.Fatal("no final result")
	}
	if !strings.Contains(screen.String(), "got:still-here") {
		t.Fatalf("shell was killed or input was dropped after the failure: %q", screen.String())
	}
	if rerr == nil || !strings.Contains(rerr.Error(), "INCOMPLETE") {
		t.Fatalf("final result must report incomplete evidence: %v", rerr)
	}
	if err := awaitServer(t, finished); err == nil {
		t.Fatal("server lost the persistence error")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
