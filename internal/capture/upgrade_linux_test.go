//go:build linux

package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// Codex 04AK: Linux counterpart of TestUpgradeWhileOldSessionRuns — a
// session of the OLD CLI keeps running and answering while a session of the
// NEW CLI starts and the new CLI reads the status; both end normally; the
// reopened encrypted database holds both sessions complete.
//
//	PENTRAIL_OLD_TEST_BINARY=<previous pentrail, -tags sqlcipher> PENTRAIL_TEST_BINARY=<new pentrail, -tags sqlcipher>
//	go test -tags sqlcipher -count=1 -v -run '^TestLinuxUpgradeWhileOldSessionRuns$' ./internal/capture
//
// Missing variables: SKIP. The same file content (SHA-256) or path for both:
// FAIL (that would pass without testing an update). Only private copies of
// both files run, in this test's own directory, with a synthetic HOME,
// database and key (environment; the key agent is not used); bash with a
// synthetic rc; no network.
//
// Every marked command is a single simple command (a separate, known
// problem records only the first command of a list `a; b` under Bash) whose
// result the shell computes, so the echo of the typed line never matches.
//
// Proven: the old session's server keeps the same PID, start time and
// executable (the private OLD copy) after the new session started and
// after the new CLI ran `status`, and the old session still answers; the
// new session's server runs the private NEW copy; `status` of the new CLI
// lists exactly both sessions, recording; both shells end with `exit`,
// both clients get the final status (exit code 0), both servers end. After
// reopening the database: two sessions, the old one recorded by the old
// version and the new one by the new version (each version string found in
// its own file), ended, no pending checkpoint bytes, no recovery; in each
// session exactly its own marked commands, each complete, end observed,
// exit code 0, output range complete (missing 0) holding its result, and no
// marker of the other session anywhere in its raw stream (missing 0).
// The final `exit` command is not asserted: its end is "session_end" by
// contract.
//
// Not covered: the key agent, autostart/setup, a schema migration, zsh,
// Windows (TestUpgradeWhileOldSessionRuns).
//
// Processes: the servers are never signalled; they end through `exit` in
// their shells — also in the emergency cleanup (through `attach`), and only
// while the PID still has the recorded start time and the private copy as
// executable (read from /proc of that PID; nothing is scanned). The test's
// directory (private copies, sockets, database) is removed only after both
// servers are gone; otherwise — also when a `start` was launched but its
// server could not be identified (the test then cannot know whether a
// server runs) — it is kept, not touched, and its path logged. Clients are
// this test's own exec.Cmd children.
func TestLinuxUpgradeWhileOldSessionRuns(t *testing.T) {
	oldSrc, newSrc := os.Getenv("PENTRAIL_OLD_TEST_BINARY"), os.Getenv("PENTRAIL_TEST_BINARY")
	if oldSrc == "" || newSrc == "" {
		t.Skip("opt-in: set PENTRAIL_OLD_TEST_BINARY (previous version) and PENTRAIL_TEST_BINARY (new version), both built with -tags sqlcipher")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required")
	}
	oldSum, newSum := luSHA(t, oldSrc), luSHA(t, newSrc)
	if oldSum == newSum || filepath.Clean(oldSrc) == filepath.Clean(newSrc) {
		t.Fatalf("old and new CLI must be two different files (old %s %s, new %s %s): identical files would pass without testing an update", oldSrc, oldSum[:12], newSrc, newSum[:12])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute) // the whole scenario
	defer cancel()

	work, err := os.MkdirTemp("", "pentrail-upgrade-linux-")
	if err != nil {
		t.Fatal(err)
	}
	if work, err = filepath.EvalSymlinks(work); err != nil {
		t.Fatal(err)
	}
	oldBin := luCopy(t, oldSrc, oldSum, filepath.Join(work, "old"))
	newBin := luCopy(t, newSrc, newSum, filepath.Join(work, "new"))
	home := filepath.Join(work, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("PS1='UP_PROMPT> '\nHISTFILE=/dev/null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const key = "synthetic-upgrade-key"
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	run := filepath.Join(home, ".pentrail", "run")
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SHELL=" + bash, "TERM=xterm", "LANG=C", "PENTRAIL_PASSPHRASE=" + key}
	t.Logf("UPGRADE old %s sha256 %s; new %s sha256 %s; work %s", oldSrc, oldSum, newSrc, newSum, work)

	var clients []*luClient
	servers := map[string]*luServer{} // socket -> server identity
	unidentified := 0                 // `start` clients whose server is not identified yet
	t.Cleanup(func() {
		for _, c := range clients {
			c.end()
		}
		gone := true
		for sock, s := range servers {
			if !s.alive() {
				continue
			}
			t.Logf("cleanup: server %d (%s) still runs — ending its shell through attach", s.pid, filepath.Base(sock))
			c := luStart(s.image, env, "attach", "--db", db, "--sock", sock)
			if c != nil {
				cctx, ccancel := context.WithTimeout(context.Background(), 20*time.Second)
				if c.soon(cctx, 0, "Detach with Ctrl-\\.") && c.raw(cctx) {
					m := c.mark()
					io.WriteString(c.f, "\x03")
					c.soon(cctx, m, "UP_PROMPT> ")
					io.WriteString(c.f, "exit\n")
				}
				ccancel()
				c.end()
			}
			if !s.waitGone(30 * time.Second) {
				gone = false
				t.Logf("cleanup: server %d (private copy %s) did not end; not signalled; work directory kept: %s", s.pid, s.image, work)
			}
		}
		switch {
		case unidentified > 0:
			t.Logf("cleanup: %d session server(s) were started but not identified; not touched; work directory kept: %s", unidentified, work)
		case gone:
			os.RemoveAll(work)
		}
	})

	// 1. old session, old file
	unidentified++
	oldC := luMust(t, luStart(oldBin, env, "start", "--db", db, "--shell", bash))
	clients = append(clients, oldC)
	oldSock := luWaitSocket(t, ctx, run, nil) // identify the server first, before anything else can fail
	oldSrv := luIdentify(t, oldSock, oldBin)
	servers[oldSock] = oldSrv
	unidentified--
	oldC.waitFor(t, ctx, 0, "UP_PROMPT> ")
	oldC.waitRaw(t, ctx)
	oldC.roundtrip(t, ctx, "echo OLD_ONE-$((10+1))", "OLD_ONE-11")

	// 2. new session, new file, while the old one runs
	unidentified++
	newC := luMust(t, luStart(newBin, env, "start", "--db", db, "--shell", bash))
	clients = append(clients, newC)
	newSock := luWaitSocket(t, ctx, run, []string{oldSock})
	newSrv := luIdentify(t, newSock, newBin)
	servers[newSock] = newSrv
	unidentified--
	newC.waitFor(t, ctx, 0, "UP_PROMPT> ")
	newC.waitRaw(t, ctx)
	if newSrv.pid == oldSrv.pid {
		t.Fatalf("both sessions report server PID %d", newSrv.pid)
	}
	oldSrv.mustLive(t, "after the new session started")
	oldC.roundtrip(t, ctx, "echo OLD_TWO-$((20+2))", "OLD_TWO-22")
	newC.roundtrip(t, ctx, "echo NEW_ONE-$((30+3))", "NEW_ONE-33")

	// 3. the new CLI reads the status of both sessions
	sctx, scancel := context.WithTimeout(ctx, 60*time.Second)
	status := exec.CommandContext(sctx, newBin, "status") // the database of the synthetic HOME (= db)
	status.Env = env
	out, err := status.CombinedOutput()
	scancel()
	if err != nil {
		t.Fatalf("new CLI status: %v\n%s", err, out)
	}
	t.Logf("UPGRADE status (new CLI):\n%s", out)
	if err := checkStatusSessions(string(out), []string{oldSock, newSock}); err != nil {
		t.Fatalf("new CLI status does not show exactly both sessions recording: %v\n%s", err, out)
	}
	if st, err := sessionio.RequestControl(oldSock, "status"); err != nil || !st.Recording {
		t.Fatalf("old session control after the new session started: %+v %v", st, err)
	}

	// 4. the old session is still the old process and still works
	oldSrv.mustLive(t, "after status of the new CLI")
	oldC.roundtrip(t, ctx, "echo OLD_THREE-$((40+4))", "OLD_THREE-44")
	newC.roundtrip(t, ctx, "echo NEW_TWO-$((50+5))", "NEW_TWO-55")
	newSrv.mustLive(t, "before exit")

	// 5. both end normally; their servers exit
	for _, c := range []*luClient{oldC, newC} {
		io.WriteString(c.f, "exit\n")
	}
	for _, c := range []*luClient{oldC, newC} {
		if err := c.wait(ctx); err != nil {
			t.Fatalf("client %s after exit: %v\n%q", c.cmd.Path, err, luTail(c.text(), 300))
		}
	}
	for sock, s := range servers {
		if !s.waitGone(30 * time.Second) {
			t.Fatalf("session server %d of %s still runs 30 s after its shell exited", s.pid, filepath.Base(sock))
		}
	}
	if luSHA(t, oldBin) != oldSum || luSHA(t, newBin) != newSum {
		t.Fatal("a private CLI copy changed during the test")
	}
	if ctx.Err() != nil {
		t.Fatal("scenario exceeded its time bound")
	}

	// 6. reopen the encrypted database
	st, err := store.Open(db, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sessions, err := st.ListSessions()
	if err != nil || len(sessions) != 2 {
		t.Fatalf("sessions %+v %v", sessions, err)
	}
	oldS, newS := sessions[0], sessions[1]
	if oldS.ID > newS.ID { // the session started first is the old one
		oldS, newS = newS, oldS
	}
	if oldS.Version == newS.Version || !luHas(t, oldBin, oldS.Version) || !luHas(t, newBin, newS.Version) {
		t.Fatalf("session versions %q (old) and %q (new) do not identify the two files", oldS.Version, newS.Version)
	}
	luCheckSession(t, st, oldS, map[string]string{"echo OLD_ONE-$((10+1))": "OLD_ONE-11", "echo OLD_TWO-$((20+2))": "OLD_TWO-22", "echo OLD_THREE-$((40+4))": "OLD_THREE-44"}, []string{"NEW_ONE", "NEW_TWO"})
	luCheckSession(t, st, newS, map[string]string{"echo NEW_ONE-$((30+3))": "NEW_ONE-33", "echo NEW_TWO-$((50+5))": "NEW_TWO-55"}, []string{"OLD_ONE", "OLD_TWO", "OLD_THREE"})
	t.Logf("UPGRADE_PASS old session %d (%s, server pid %d start %s, private old copy) kept running and answering after new session %d (%s, server pid %d, private new copy) started and the new CLI read the status; both ended normally; reopened database: both sessions ended, no pending bytes, no recovery, own commands complete with exit 0, missing 0",
		oldS.ID, oldS.Version, oldSrv.pid, oldSrv.start, newS.ID, newS.Version, newSrv.pid)
}

func luCheckSession(t *testing.T, st *store.Store, s store.SessionInfo, want map[string]string, foreign []string) {
	t.Helper()
	if s.EndedMs <= 0 || s.PendingBytes != 0 || s.Recoveries != 0 {
		t.Fatalf("session %d: ended %d, pending bytes %d, recoveries %d (want ended, 0, 0)", s.ID, s.EndedMs, s.PendingBytes, s.Recoveries)
	}
	raw, missing, err := st.ReadRange(s.ID, 0, s.RawBytes)
	if err != nil || missing != 0 {
		t.Fatalf("session %d raw: missing %d err %v", s.ID, missing, err)
	}
	for _, f := range foreign {
		if bytes.Contains(raw, []byte(f)) {
			t.Fatalf("session %d holds %q of the other session", s.ID, f)
		}
	}
	cmds, err := st.ListCommands(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	for text, result := range want {
		n := 0
		for _, c := range cmds {
			if c.Command != text {
				continue
			}
			n++
			if !c.Complete || c.EndReason != "" || c.ExitCode != 0 || c.EndedMs <= 0 {
				t.Fatalf("session %d command %q: complete %v, end reason %q, exit %d, ended %d", s.ID, text, c.Complete, c.EndReason, c.ExitCode, c.EndedMs)
			}
			out, miss, err := st.ReadRange(s.ID, c.OutStartOff, c.OutEndOff)
			if err != nil || miss != 0 || c.RawMissing != 0 || !bytes.Contains(out, []byte(result+"\r\n")) {
				t.Fatalf("session %d command %q: range %d..%d missing %d/%d err %v, result %q present %v", s.ID, text, c.OutStartOff, c.OutEndOff, miss, c.RawMissing, err, result, bytes.Contains(out, []byte(result)))
			}
		}
		if n != 1 {
			t.Fatalf("session %d: command %q recorded %d times, want 1", s.ID, text, n)
		}
	}
	for _, c := range cmds {
		for _, f := range foreign {
			if strings.Contains(c.Command, f) {
				t.Fatalf("session %d records command %q of the other session", s.ID, c.Command)
			}
		}
	}
}

// --- helpers of this test ---

func luSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func luCopy(t *testing.T, src, sum, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "pentrail")
	if err := os.WriteFile(dst, b, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := luSHA(t, dst); got != sum {
		t.Fatalf("private copy of %s: sha256 %s, source %s", src, got, sum)
	}
	return dst
}

func luHas(t *testing.T, bin, s string) bool {
	t.Helper()
	b, err := os.ReadFile(bin)
	return err == nil && s != "" && bytes.Contains(b, []byte(s))
}

// luWaitSocket: the one new socket (not in known) in the private run
// directory that accepts a connection, within the bound (`start` connects
// its client only after its server listens).
func luWaitSocket(t *testing.T, ctx context.Context, run string, known []string) string {
	t.Helper()
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		all, _ := filepath.Glob(filepath.Join(run, "*.sock"))
		var fresh []string
		for _, s := range all {
			old := false
			for _, k := range known {
				old = old || s == k
			}
			if !old {
				fresh = append(fresh, s)
			}
		}
		if len(fresh) > 1 {
			t.Fatalf("more than one new session socket in %s: %v (known %v)", run, fresh, known)
		}
		if len(fresh) == 1 {
			if c, err := net.DialTimeout("unix", fresh[0], time.Second); err == nil {
				c.Close()
				return fresh[0]
			}
		}
		select {
		case <-wctx.Done():
			t.Fatalf("no new listening session socket in %s within the bound (known %v)", run, known)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

type luClient struct {
	cmd    *exec.Cmd
	f      *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	done   chan struct{}
	err    error
	closed bool
}

func luMust(t *testing.T, c *luClient) *luClient {
	t.Helper()
	if c == nil {
		t.Fatal("client did not start")
	}
	return c
}

func luStart(bin string, env []string, args ...string) *luClient {
	c := &luClient{cmd: exec.Command(bin, args...), done: make(chan struct{})}
	c.cmd.Env = env
	f, err := pty.StartWithSize(c.cmd, &pty.Winsize{Rows: 24, Cols: 100})
	if err != nil {
		return nil
	}
	c.f = f
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			c.mu.Lock()
			c.out.Write(buf[:n])
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() { c.err = c.cmd.Wait(); close(c.done) }()
	return c
}

func (c *luClient) text() string { c.mu.Lock(); defer c.mu.Unlock(); return c.out.String() }
func (c *luClient) mark() int    { c.mu.Lock(); defer c.mu.Unlock(); return c.out.Len() }

func (c *luClient) soon(ctx context.Context, mark int, s string) bool {
	for {
		if txt := c.text(); len(txt) >= mark && strings.Contains(txt[mark:], s) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (c *luClient) waitFor(t *testing.T, ctx context.Context, mark int, s string) {
	t.Helper()
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if !c.soon(wctx, mark, s) {
		t.Fatalf("client %s: no %q within the bound; tail %q", c.cmd.Path, s, luTail(c.text(), 300))
	}
}

// raw: the client has put its terminal into raw mode (before that, typed
// input would be echoed by the client's own terminal, not by the session).
func (c *luClient) raw(ctx context.Context) bool {
	for {
		if tio, err := unix.IoctlGetTermios(int(c.f.Fd()), unix.TCGETS); err == nil && tio.Lflag&(unix.ECHO|unix.ICANON) == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (c *luClient) waitRaw(t *testing.T, ctx context.Context) {
	t.Helper()
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !c.raw(wctx) {
		t.Fatalf("client %s: terminal not in raw mode within the bound", c.cmd.Path)
	}
}

func (c *luClient) roundtrip(t *testing.T, ctx context.Context, cmd, result string) {
	t.Helper()
	m := c.mark()
	if _, err := io.WriteString(c.f, cmd+"\n"); err != nil {
		t.Fatal(err)
	}
	c.waitFor(t, ctx, m, result+"\r\n")
}

// wait: the client's own exit within the scenario's bound.
func (c *luClient) wait(ctx context.Context) error {
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	select {
	case <-c.done:
		c.close()
		return c.err
	case <-wctx.Done():
		return fmt.Errorf("did not exit within the bound")
	}
}

func (c *luClient) close() {
	if !c.closed {
		c.closed = true
		c.f.Close()
	}
}

// end (cleanup): a client still running is this test's own exec.Cmd child;
// it is ended through that Cmd, with a bounded wait.
func (c *luClient) end() {
	select {
	case <-c.done:
	default:
		c.cmd.Process.Kill()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
		}
	}
	c.close()
}

// luServer: a session server identified by PID (from the socket's peer
// credentials), start time and executable, read from /proc of that PID.
type luServer struct {
	pid          int
	start, image string
}

func luProc(pid int) (start, image string, ok bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", "", false
	}
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return "", "", false
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 20 || f[0] == "Z" { // f[0]: state; f[19]: start time
		return "", "", false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", "", false
	}
	return f[19], exe, true
}

func luIdentify(t *testing.T, sock, bin string) *luServer {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || credErr != nil || cred == nil || cred.Pid <= 0 {
		t.Fatalf("peer credentials of %s: %v %v", sock, err, credErr)
	}
	start, image, ok := luProc(int(cred.Pid))
	if !ok || image != bin {
		t.Fatalf("session server %d of %s: executable %q, want the private copy %q", cred.Pid, filepath.Base(sock), image, bin)
	}
	return &luServer{pid: int(cred.Pid), start: start, image: image}
}

func (s *luServer) alive() bool {
	start, image, ok := luProc(s.pid)
	return ok && start == s.start && image == s.image
}

func (s *luServer) mustLive(t *testing.T, when string) {
	t.Helper()
	if !s.alive() {
		t.Fatalf("session server %d (start %s, %s) is not the same running process %s", s.pid, s.start, s.image, when)
	}
}

func (s *luServer) waitGone(d time.Duration) bool {
	for t0 := time.Now(); time.Since(t0) < d; time.Sleep(50 * time.Millisecond) {
		if !s.alive() {
			return true
		}
	}
	return false
}

func luTail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
