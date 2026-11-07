//go:build windows

package capture

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
)

// Codex iteration 02, finding 3: positive native test of the CMD observer in
// a real cmd.exe under a real ConPTY, driven through the real session server
// and session protocol (the way `pentrail attach` types), stored in a real
// Store. Synthetic data only, isolated temp directory.
//
// Each command prints a unique token that differs from its own command text
// (`echo NAT^_ONE` prints NAT_ONE), so "the command ran" and "its output is in
// its range" can be checked without confusing the echo with the output.

type nativeCMD struct {
	t      *testing.T
	st     *store.Store
	id     int64
	db     string
	conn   net.Conn
	w      *sessionio.Writer
	mu     sync.Mutex
	screen bytes.Buffer
	ended  chan struct{}
	// served is closed when this test's own RunServer returned; serveErr is
	// its result.
	served   chan struct{}
	serveErr error
	sock     string
	shell    windows.Handle // this test's own cmd.exe (held from start: no PID reuse)
	ev       *cmdEvidence   // nil unless PENTRAIL_CMD_EVIDENCE_DIR is set

	// 04D, under mu: counted as frames arrive (no rescan of the whole
	// screen per poll, which costs O(screen) and slowed the client on
	// large outputs)
	markers   int
	carry     []byte // unscanned tail that may hold the start of a marker
	recvBytes int64
	lastRecv  time.Time
	readEnd   string // why the client's read loop ended
}

const (
	nativeKey = "synthetic-native-cmd-key"
	nativeTok = "native-cmd-test-token"
)

// startNativeCMD: with a failure trace kept in memory and written out only
// if the test fails (Codex 04I), unless PENTRAIL_CMD_EVIDENCE_DIR selects
// the streamed evidence folder.
func startNativeCMD(t *testing.T) *nativeCMD {
	t.Helper()
	return startNativeCMDWith(t, true)
}

// startNativeCMDUntraced: no in-memory trace (timing and heap tests; the
// trace copies every output chunk under the capture lock).
func startNativeCMDUntraced(t *testing.T) *nativeCMD {
	t.Helper()
	return startNativeCMDWith(t, false)
}

func startNativeCMDWith(t *testing.T, memTrace bool) *nativeCMD {
	t.Helper()
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	if !strings.EqualFold(filepath.Base(comspec), "cmd.exe") {
		t.Skipf("ComSpec is %q, not cmd.exe", comspec)
	}
	dir := t.TempDir()
	// Evidence first: a misconfigured evidence folder fails the test before
	// anything is opened (Codex 04H: a Fatal with the store still open left
	// the DB in use when TempDir was removed).
	ev := newCmdEvidence(t, memTrace)
	db := filepath.Join(dir, "evidence.db")
	st, err := store.Open(db, []byte(nativeKey))
	if err != nil {
		t.Fatal(err)
	}
	// Closed on every path, also after any later Fatal (Close is
	// idempotent; registered first, so it runs after shutdown).
	t.Cleanup(func() { st.Close() })
	id, err := st.StartSession("cmd.exe", "native-test", "test")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly as runtime_windows.go sets it (capture.CMDPrompt): the marker
	// carries the prompt's visible text and is closed by BEL.
	t.Setenv("PROMPT", CMDPrompt(nativeTok, "$P$G"))
	n := &nativeCMD{t: t, st: st, id: id, db: db, ended: make(chan struct{}), served: make(chan struct{})}
	n.sock = filepath.Join(dir, "s.sock")
	n.ev = ev
	if n.ev != nil {
		cmdTraceHook = n.ev.traceEvent
		// registered before shutdown, so it runs AFTER it (server finished)
		t.Cleanup(func() { cmdTraceHook = nil; n.ev.close(t, n) })
	}
	go func() {
		n.serveErr = RunServer(Options{Shell: comspec, Args: []string{"/D", "/Q", "/K", "chcp 65001>nul"},
			Store: st, SessionID: id, MarkerToken: nativeTok}, n.sock)
		close(n.served)
	}()
	// Registered before anything can fail: on t.Fatal it ends THIS test's
	// shell (and only it) so its RunServer returns and the DB is released
	// before TempDir removal.
	t.Cleanup(n.shutdown)
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := localipc.Dial(n.sock, 2*time.Second)
		if err == nil {
			n.conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session endpoint: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	n.ownShell()
	n.w = sessionio.NewWriter(n.conn)
	if err := n.w.Send(sessionio.Hello, []byte(sessionio.Version)); err != nil {
		t.Fatal(err)
	}
	if typ, b, err := sessionio.Read(n.conn); err != nil || typ != sessionio.Hello || string(b) != sessionio.Version {
		t.Fatalf("hello: %d %q %v", typ, b, err)
	}
	go func() {
		defer close(n.ended)
		for {
			typ, b, err := sessionio.Read(n.conn)
			if err != nil || typ != sessionio.Output {
				n.mu.Lock()
				n.readEnd = fmt.Sprintf("frame type %d, err %v, after %d bytes", typ, err, n.recvBytes)
				n.mu.Unlock()
				return
			}
			n.ev.frame("recv", b)
			n.mu.Lock()
			n.screen.Write(b)
			n.recvBytes += int64(len(b))
			n.lastRecv = time.Now()
			n.countMarkers(b)
			n.mu.Unlock()
			if bytes.Contains(b, []byte("\x1b[6n")) {
				n.ev.frame("sent", []byte("\x1b[1;1R"))
				n.w.Send(sessionio.Data, []byte("\x1b[1;1R"))
			}
		}
	}()
	n.waitPrompts(1)
	return n
}

// ownShell opens a handle to the shell started by this test's own RunServer
// (its PID comes from that server's control endpoint). Holding the handle
// from the start rules out PID reuse when it is used in shutdown.
func (n *nativeCMD) ownShell() {
	if n.shell != 0 {
		return
	}
	state, err := sessionio.RequestControl(n.sock, "status")
	if err != nil || state.RootPID <= 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(state.RootPID))
	if err == nil {
		n.shell = h
	}
}

// shutdown runs at test end, also after t.Fatal. It never touches other
// cmd/pentrail processes: first `exit`, then (if this test's shell is still
// alive) terminates exactly that shell; RunServer then sees EOF, finishes
// and closes the store, so TempDir can be removed.
func (n *nativeCMD) shutdown() {
	defer func() {
		if n.shell != 0 {
			windows.CloseHandle(n.shell)
			n.shell = 0
		}
	}()
	wait := func(d time.Duration) bool {
		select {
		case <-n.served:
			return true
		case <-time.After(d):
			return false
		}
	}
	if !wait(0) {
		n.ownShell()
		if n.w != nil {
			n.ev.frame("sent", []byte("\x03\rexit\r"))
			n.w.Send(sessionio.Data, []byte("\x03\rexit\r"))
		}
		if !wait(5*time.Second) && n.shell != 0 {
			windows.TerminateProcess(n.shell, 1)
			windows.WaitForSingleObject(n.shell, 10000)
		}
		if !wait(30 * time.Second) {
			n.t.Errorf("this test's session server did not finish")
		}
	}
	if n.conn != nil {
		n.conn.Close()
	}
	n.st.Close() // idempotent; RunServer already closed it on a normal end
}

func (n *nativeCMD) text() string { n.mu.Lock(); defer n.mu.Unlock(); return n.screen.String() }

func (n *nativeCMD) waitFor(s string) {
	n.t.Helper()
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		if strings.Contains(n.text(), s) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n.fatalf("waiting for %q; screen tail %q", s, tail(n.text(), 400))
}

// prompts counts authenticated prompt markers on the screen so far.
var nativeMarker = regexp.MustCompile("\x1b\\]697;" + regexp.QuoteMeta(nativeTok) + ";A(;[^\x07\x1b]*)?\x07")

// prompts counts complete, terminated prompt markers (with or without the
// prompt text) received so far.
func (n *nativeCMD) prompts() int { n.mu.Lock(); defer n.mu.Unlock(); return n.markers }

// countMarkers (under mu) counts the markers completed by b; a marker split
// across frames is completed from carry.
func (n *nativeCMD) countMarkers(b []byte) {
	s := append(n.carry, b...)
	end := 0
	for _, m := range nativeMarker.FindAllIndex(s, -1) {
		n.markers++
		end = m[1]
	}
	rest := s[end:]
	if i := bytes.LastIndexByte(rest, 0x1b); i >= 0 && len(rest)-i < 4096 {
		n.carry = append([]byte(nil), rest[i:]...) // possibly a marker's start
	} else {
		n.carry = nil
	}
}

func (n *nativeCMD) waitPrompts(k int) {
	n.t.Helper()
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		if n.prompts() >= k {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n.fatalf("waiting for %d prompts; screen tail %q", k, tail(n.text(), 400))
}

// typeFrames sends each element as its own Data frame (splits inside words,
// between CR and LF, inside multi-byte UTF-8 sequences are all deliberate).
func (n *nativeCMD) typeFrames(frames ...string) {
	n.t.Helper()
	for _, f := range frames {
		n.ev.frame("sent", []byte(f))
		if err := n.w.Send(sessionio.Data, []byte(f)); err != nil {
			n.t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// finish waits for the shell to exit and the server to close the store, then
// reopens the database like the viewer would.
func (n *nativeCMD) finish() (*store.Store, store.SessionInfo, []store.CommandInfo, string) {
	n.t.Helper()
	select {
	case <-n.ended:
	case <-time.After(40 * time.Second):
		n.fatalf("cmd did not exit; screen tail %q", tail(n.text(), 400))
	}
	select {
	case <-n.served:
		if n.serveErr != nil {
			n.fatalf("session server: %v", n.serveErr)
		}
	case <-time.After(30 * time.Second):
		n.fatalf("session server did not finish")
	}
	re, err := store.Open(n.db, []byte(nativeKey))
	if err != nil {
		n.fatalf("%v", err)
	}
	n.t.Cleanup(func() { re.Close() })
	ss, err := re.ListSessions()
	if err != nil || len(ss) != 1 {
		n.fatalf("sessions %+v %v", ss, err)
	}
	n.ev.dump(n, re) // evidence first, before any assertion can fail
	cmds, err := re.ListCommands(n.id)
	if err != nil {
		n.fatalf("%v", err)
	}
	raw, missing, err := re.ReadRange(n.id, 0, ss[0].RawBytes)
	if err != nil || missing != 0 {
		n.fatalf("raw log: missing=%d err=%v", missing, err)
	}
	return re, ss[0], cmds, string(raw)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// checkCommon: properties that must hold whatever cmd does with the input.
func checkCommon(n *nativeCMD, re *store.Store, id int64, sess store.SessionInfo, cmds []store.CommandInfo, submitted []string, raw string) {
	n.t.Helper()
	for i, c := range cmds {
		if c.Index != int64(i) {
			n.fatalf("indices not contiguous: %+v", cmds)
		}
		known := false
		for _, s := range submitted {
			if c.Command == s {
				known = true
			}
		}
		if !known {
			n.fatalf("command %q was not submitted as a whole line (guessed or merged): %+v", c.Command, cmds)
		}
		// on the rendered screen, not in the byte stream: ConPTY splits an
		// echo with markers and VT sequences and repaints wrapped cells
		if !echoedOnScreen([]byte(raw), c.Command) {
			n.fatalf("command %q recorded but no such echo on the rendered screen", c.Command)
		}
		if c.EndedMs == 0 || c.OutEndOff < c.OutStartOff || c.OutEndOff > sess.RawBytes {
			n.fatalf("command %d not closed with a valid range: %+v (raw %d)", i, c, sess.RawBytes)
		}
		if c.Complete || c.ExitCode != -1 {
			n.fatalf("CMD never reports an exit status, but %q claims one: %+v", c.Command, c)
		}
		if c.EndReason != "" && c.EndReason != store.EndSessionEnded {
			n.fatalf("unexpected end reason: %+v", c)
		}
	}
	for i, c := range cmds {
		if c.EndReason == store.EndSessionEnded && i != len(cmds)-1 {
			n.fatalf("only the last command can end with the session: %+v", cmds)
		}
	}
}

// outputIn returns the command whose text is cmd and checks that token is in
// its stored output range.
func outputIn(n *nativeCMD, re *store.Store, id int64, cmds []store.CommandInfo, cmd, token string) store.CommandInfo {
	n.t.Helper()
	for _, c := range cmds {
		if c.Command == cmd {
			b, missing, err := re.ReadRange(id, c.OutStartOff, c.OutEndOff)
			if err != nil || missing != 0 || !strings.Contains(string(b), token) {
				n.fatalf("%q: output range %d..%d does not contain %q: %q (missing=%d err=%v)", cmd, c.OutStartOff, c.OutEndOff, token, b, missing, err)
			}
			return c
		}
	}
	n.fatalf("command %q not recorded: %+v", cmd, cmds)
	return store.CommandInfo{}
}

// CR and CRLF (also split between frames), a split inside a word and inside
// a UTF-8 sequence, a pasted block, program stdin (set /p), and a final
// command followed at once by `exit` (cmd may exit without painting another
// prompt — the Codex counter-example).
func TestNativeCMDPasteSplitUnicodeStdinAndFinalCommand(t *testing.T) {
	n := startNativeCMD(t)
	uni := "echo ŻÓŁĆ^_gęślą^_ü" // prints ŻÓŁĆ_gęślą_ü
	ub := []byte(uni)
	cut := bytes.IndexByte(ub, 0x93) // inside the 2-byte "Ó" (C3 93)
	if cut <= 0 {
		cut = 7
	}
	step := func(waitText string, frames ...string) {
		t.Helper()
		p := n.prompts()
		n.typeFrames(frames...)
		if waitText != "" {
			n.waitFor(waitText)
		}
		n.waitPrompts(p + 1)
	}
	step("NAT_ONE", "echo NAT^_O", "NE\r")                        // split inside a word, CR
	step("NAT_TWO", "echo NAT^_TWO\r", "\n")                      // CRLF split across frames
	step("NAT_THREE", "echo NAT^_THREE\r\n")                      // CRLF in one frame
	step("ŻÓŁĆ_gęślą_ü", string(ub[:cut]), string(ub[cut:])+"\r") // split inside a UTF-8 sequence
	p := n.prompts()
	n.typeFrames("echo NAT^_P1\recho NAT^_P2\recho NAT^_P3\r") // pasted block
	n.waitFor("NAT_P3")
	n.waitPrompts(p + 3)
	p = n.prompts()
	n.typeFrames("set /p V=PODAJ^_TEKST: \r")
	n.waitFor("PODAJ_TEKST: ")
	n.typeFrames("synthetic-stdin-line\r") // program input, not a command
	n.waitPrompts(p + 1)
	n.typeFrames("echo NAT^_FINAL\rexit\r") // final command, then exit at once
	re, sess, cmds, raw := n.finish()

	submitted := []string{"echo NAT^_ONE", "echo NAT^_TWO", "echo NAT^_THREE", uni,
		"echo NAT^_P1", "echo NAT^_P2", "echo NAT^_P3", "set /p V=PODAJ^_TEKST: ", "echo NAT^_FINAL", "exit"}
	checkCommon(n, re, n.id, sess, cmds, submitted, raw)
	for _, c := range []struct{ cmd, token string }{
		{"echo NAT^_ONE", "NAT_ONE"}, {"echo NAT^_TWO", "NAT_TWO"}, {"echo NAT^_THREE", "NAT_THREE"},
		{uni, "ŻÓŁĆ_gęślą_ü"}, {"echo NAT^_P1", "NAT_P1"}, {"echo NAT^_P2", "NAT_P2"}, {"echo NAT^_P3", "NAT_P3"},
		{"echo NAT^_FINAL", "NAT_FINAL"},
	} {
		outputIn(n, re, n.id, cmds, c.cmd, c.token)
	}
	for _, c := range cmds {
		if strings.Contains(c.Command, "synthetic-stdin-line") {
			n.fatalf("program input recorded as a command: %+v", c)
		}
	}
	// `exit` is either a confirmed command (cmd painted its echo) or counted
	// as unattributed; the stdin line is always unattributed.
	exitCmd := false
	for _, c := range cmds {
		if c.Command == "exit" {
			exitCmd = true
		}
	}
	want := int64(1)
	if !exitCmd {
		want = 2
	}
	if sess.Unattributed != want {
		n.fatalf("unattributed lines = %d, want %d (stdin line%s): %+v", sess.Unattributed, want, map[bool]string{true: "", false: " + never-echoed exit"}[exitCmd], cmds)
	}
	t.Logf("NATIVE_CMD commands=%d exit_confirmed=%v unattributed=%d last=%+v", len(cmds), exitCmd, sess.Unattributed, cmds[len(cmds)-1])
}

// A bare LF from a client (scripts, some paste paths). What cmd/ConPTY do
// with it is not assumed; the recorder must stay safe: nothing guessed or
// merged, every recorded command closed with a valid range, and every line
// that demonstrably ran (its token is on screen) is recorded.
func TestNativeCMDBareLF(t *testing.T) {
	n := startNativeCMD(t)
	p := n.prompts()
	n.typeFrames("echo LFNAT^_ONE\n")
	time.Sleep(time.Second)
	n.typeFrames("\r") // in case LF was not taken as Enter
	n.waitPrompts(p + 1)
	p = n.prompts()
	n.typeFrames("echo LFNAT^_END\r")
	n.waitFor("LFNAT_END")
	n.waitPrompts(p + 1)
	n.typeFrames("exit\r")
	re, sess, cmds, raw := n.finish()
	submitted := []string{"echo LFNAT^_ONE", "echo LFNAT^_END", "exit"}
	checkCommon(n, re, n.id, sess, cmds, submitted, raw)
	ran := strings.Contains(strings.ReplaceAll(raw, "echo LFNAT^_ONE", ""), "LFNAT_ONE")
	if ran {
		outputIn(n, re, n.id, cmds, "echo LFNAT^_ONE", "LFNAT_ONE")
	}
	outputIn(n, re, n.id, cmds, "echo LFNAT^_END", "LFNAT_END")
	t.Logf("NATIVE_CMD_LF first_line_ran=%v commands=%d unattributed=%d", ran, len(cmds), sess.Unattributed)
}

// off/on between prompts (Codex 04B): nothing typed or shown while paused
// is recorded or attributed; the prompt painted during the pause takes the
// first command typed after resuming, with its output.
func TestNativeCMDOffOn(t *testing.T) {
	n := startNativeCMD(t)
	p := n.prompts()
	n.typeFrames("echo REC^_ONE\r")
	n.waitFor("REC_ONE")
	n.waitPrompts(p + 1)
	if st, err := sessionio.RequestControl(n.sock, "off"); err != nil || st.Recording {
		n.fatalf("off: %+v %v", st, err)
	}
	p = n.prompts()
	n.typeFrames("echo PRIV^_ATE\r")
	n.waitFor("PRIV_ATE")
	n.waitPrompts(p + 1)
	if st, err := sessionio.RequestControl(n.sock, "on"); err != nil || !st.Recording {
		n.fatalf("on: %+v %v", st, err)
	}
	p = n.prompts()
	n.typeFrames("echo REC^_TWO\r")
	n.waitFor("REC_TWO")
	n.waitPrompts(p + 1)
	n.typeFrames("exit\r")
	re, sess, cmds, raw := n.finish()
	if strings.Contains(raw, "PRIV_ATE") || strings.Contains(raw, "PRIV^_ATE") {
		n.fatalf("paused input/output in the recorded stream")
	}
	submitted := []string{"echo REC^_ONE", "echo REC^_TWO", "exit"}
	checkCommon(n, re, n.id, sess, cmds, submitted, raw)
	outputIn(n, re, n.id, cmds, "echo REC^_ONE", "REC_ONE")
	outputIn(n, re, n.id, cmds, "echo REC^_TWO", "REC_TWO")
	if len(cmds) < 2 || cmds[0].Command != "echo REC^_ONE" || cmds[1].Command != "echo REC^_TWO" {
		n.fatalf("commands %+v", cmds)
	}
	t.Logf("NATIVE_CMD_OFFON commands=%d unattributed=%d", len(cmds), sess.Unattributed)
}
