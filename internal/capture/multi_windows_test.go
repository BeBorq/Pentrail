//go:build windows

package capture

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
)

// Codex 04Y: four terminals at once under output — PowerShell 5.1,
// PowerShell 7 and two CMD — with `off` called from a separate CLI while all
// of them are printing, a private phase during the pause, `on`, and more
// output. Synthetic HOME, database and payloads; a private copy of the CLI;
// only processes whose image is that copy are ever ended.
//
// Opt-in:
//
//	PENTRAIL_MULTI_TERMINALS=1 PENTRAIL_TEST_BINARY=<pentrail.exe (SQLCipher)>
//	go test -tags sqlcipher -count=1 -v -run TestWindowsFourTerminalsUnderOutput ./internal/capture
//
// Phases per session (sizes per session): A 128 KiB recorded; L — a bounded
// producer (TestMultiTerminalProducer, run from a private copy of this test
// binary) that prints paced lines until the test creates its stop file, or
// until its own limit (producerMaxLines / producerMaxRun), and on exit
// writes a done file naming why it ended. Codex 04AA: the 04Y run showed
// 0 of 4 sessions printing when `off` returned (fixed-size files had
// already ended), so now: `status`/`off` start only after every session
// printed L line 100, and the test FAILS unless all four producers are
// still running (no done file) after `off` returned; session 4 is stopped
// first and the echo probe there FAILS unless sessions 1–3 are still
// running after it; every producer must have ended by its stop file, not
// its limit. L lines are NOT checked either way, because bytes printed
// before `off` was acknowledged may or may not be recorded; P 32 KiB with a random private token while
// paused — the token must appear nowhere in the database; B 128 KiB after
// `on`. Every phase ends with its END line, and the test waits for it before
// the next step (explicit phase boundaries).
//
// Checked after both a normal exit and a reopen of the encrypted database:
// 4 sessions with the expected shells; for A and B every line, in order, in
// the session's recorded stream (ConPTY renders the output: compared on the
// visible text without escape sequences, lines are unique and have no
// spaces); the first and END line inside the A/B command's output range;
// the A and B commands recorded with their exact text, the P command not;
// missing 0; no line of another session in a session. Reported:
// `status`/`off`/`on` round trip while printing, an echo round trip in
// session 4 while others print, phase durations, how many L lines were
// recorded.
//
// Does NOT prove: byte-exact application output on Windows (ConPTY renders
// it); behaviour of the key agent across off (no agent runs before the
// test's `on`); Linux (pending: same scenario with 2 Bash + 2 Zsh, not yet
// written).
func TestWindowsFourTerminalsUnderOutput(t *testing.T) {
	src := os.Getenv("PENTRAIL_TEST_BINARY")
	if os.Getenv("PENTRAIL_MULTI_TERMINALS") != "1" || src == "" {
		t.Skip("opt-in: set PENTRAIL_MULTI_TERMINALS=1 and PENTRAIL_TEST_BINARY to a SQLCipher pentrail.exe")
	}
	if _, err := exec.LookPath("pwsh.exe"); err != nil {
		t.Skip("PowerShell 7 (pwsh.exe) is not installed: the scenario needs PS 5.1 + PS 7 + 2 CMD")
	}
	src = absClean(t, src)
	bin := privateCopy(t, src, fileSHA(t, src), "cli")
	own := []string{bin}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self = absClean(t, self)
	producer := privateCopy(t, self, fileSHA(t, self), "producer") // never killed: it ends on its stop file or its own limit

	home := t.TempDir()
	const key = "synthetic-multi-terminal-key"
	for k, v := range map[string]string{"USERPROFILE": home, "HOME": home, "LOCALAPPDATA": filepath.Join(home, "Local"), "APPDATA": filepath.Join(home, "Roaming"),
		"PENTRAIL": "", "PENTRAIL_SOCKET": "", "PENTRAIL_SESSION": "", "PENTRAIL_DB": "", "PENTRAIL_PASSPHRASE": key} {
		t.Setenv(k, v)
	}
	run := filepath.Join(home, ".pentrail", "run")
	servers := map[string]windows.Handle{}
	t.Cleanup(func() { cleanupOwnServers(home, own, servers) })

	tokenBytes := make([]byte, 12)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := "PRIV" + hex.EncodeToString(tokenBytes) + "-"
	data := t.TempDir()
	type sess struct {
		shell, wantShell string
		ps               bool
		screen           *testScreen
		sock             string
		ph               map[string]payloadPhase
	}
	sessions := []*sess{{shell: "powershell", wantShell: "powershell.exe", ps: true}, {shell: "pwsh", wantShell: "pwsh.exe", ps: true},
		{shell: "cmd", wantShell: "cmd.exe"}, {shell: "cmd", wantShell: "cmd.exe"}}
	sizes := map[string]int{"A": 128 << 10, "P": 32 << 10, "B": 128 << 10}
	ctl := t.TempDir() // stop-<n> (test -> producer) and done-<n> (producer -> test)
	t.Cleanup(func() { // a failed test still ends every producer at its next check
		for i := range sessions {
			os.WriteFile(filepath.Join(ctl, fmt.Sprintf("stop-%d", i+1)), nil, 0o600)
		}
	})
	for i, s := range sessions {
		s.ph = map[string]payloadPhase{}
		for _, ph := range []string{"A", "P", "B"} {
			n := sizes[ph]
			tok := ""
			if ph == "P" {
				tok = token
			}
			p, err := makePhase(data, i+1, ph, tok, n)
			if err != nil {
				t.Fatal(err)
			}
			s.ph[ph] = p
		}
	}
	command := func(s *sess, ph string) string {
		if ph == "L" {
			n := strconv.Itoa(slices.Index(sessions, s) + 1)
			if s.ps {
				return "& '" + strings.ReplaceAll(producer, "'", "''") + "' '-test.run=TestMultiTerminalProducer' " + n + " '" + strings.ReplaceAll(ctl, "'", "''") + "'"
			}
			return `"` + producer + `" -test.run=TestMultiTerminalProducer ` + n + ` "` + ctl + `"`
		}
		if s.ps {
			return "Get-Content -LiteralPath '" + strings.ReplaceAll(s.ph[ph].path, "'", "''") + "'"
		}
		return `type "` + s.ph[ph].path + `"`
	}
	waitLong := func(s *sess, v string, d time.Duration) time.Duration {
		t.Helper()
		t0 := time.Now()
		for time.Since(t0) < d {
			if strings.Contains(s.screen.text(), v) {
				return time.Since(t0)
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: waiting %v for %q; tail %q", s.wantShell, d, v, tail(s.screen.text(), 300))
		return 0
	}
	var socks []string
	for _, s := range sessions {
		s.screen = openScreen(t, bin, []string{"start", "--shell", s.shell})
		s.screen.wait(t, ";A\a")
		s.sock = newSocket(t, run, socks)
		socks = append(socks, s.sock)
		serverPID(t, s.sock, bin, own, servers)
	}
	report := []string{}
	phase := func(ph string) time.Duration {
		t0 := time.Now()
		for _, s := range sessions {
			s.screen.send(t, command(s, ph))
		}
		for _, s := range sessions {
			waitLong(s, s.ph[ph].end(), 5*time.Minute)
		}
		return time.Since(t0)
	}

	// A: all four print at once, recording
	report = append(report, fmt.Sprintf("phase A %v", phase("A").Round(time.Millisecond)))

	// L: all four producers print; status, off from a separate CLI meanwhile
	done := func(i int) (bool, string) {
		b, err := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("done-%d", i+1)))
		return err == nil, string(b)
	}
	stop := func(i int) {
		if err := os.WriteFile(filepath.Join(ctl, fmt.Sprintf("stop-%d", i+1)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustRun := func(when string, idx ...int) {
		t.Helper()
		for _, i := range idx {
			if ended, why := done(i); ended {
				t.Fatalf("producer of session %d had already ended (%s) %s: not proven under output", i+1, why, when)
			}
		}
	}
	tL := time.Now()
	for _, s := range sessions {
		s.screen.send(t, command(s, "L"))
	}
	for i, s := range sessions { // handshake: output has really started everywhere
		waitLong(s, fmt.Sprintf("S%d-L-000100-", i+1), 2*time.Minute)
	}
	mustRun("before status", 0, 1, 2, 3)
	t0 := time.Now()
	st := runCLI(t, bin, "status")
	report = append(report, fmt.Sprintf("status while printing %v", time.Since(t0).Round(time.Millisecond)))
	if err := checkStatusSessions(st, socks); err != nil {
		t.Fatalf("status during output: %v\n%s", err, st)
	}
	t0 = time.Now()
	runCLI(t, bin, "off")
	offTook := time.Since(t0)
	mustRun("when off returned", 0, 1, 2, 3) // started before status, still running after off
	report = append(report, fmt.Sprintf("off while printing %v (producers running before status and after off: 4 of 4)", offTook.Round(time.Millisecond)))
	// session 4 stops; echo round trip there while 1–3 keep printing
	stop(3)
	waitLong(sessions[3], "S4-L-END", time.Minute)
	mustRun("before the echo probe", 0, 1, 2)
	t0 = time.Now()
	sessions[3].screen.send(t, "echo ECHO^_PROBE")
	waitLong(sessions[3], "ECHO_PROBE", time.Minute)
	echoTook := time.Since(t0)
	mustRun("when the echo probe returned", 0, 1, 2)
	report = append(report, fmt.Sprintf("echo round trip in session 4 %v (others printing before and after it: 3 of 3)", echoTook.Round(time.Millisecond)))
	for i := range sessions[:3] {
		stop(i)
	}
	for i, s := range sessions {
		waitLong(s, fmt.Sprintf("S%d-L-END", i+1), time.Minute)
		var why string
		for t1 := time.Now(); time.Since(t1) < time.Minute; time.Sleep(20 * time.Millisecond) {
			var ended bool
			if ended, why = done(i); ended {
				break
			}
		}
		if why != "stop" {
			t.Fatalf("producer of session %d ended by %q, want its stop file", i+1, why)
		}
	}
	report = append(report, fmt.Sprintf("phase L %v", time.Since(tL).Round(time.Millisecond)))
	if st = runCLI(t, bin, "status"); checkStatusSessionsState(st, socks, false) != nil {
		t.Fatalf("after off not all four paused:\n%s", st)
	}

	// P: private output while paused; shells keep working
	report = append(report, fmt.Sprintf("phase P (paused) %v", phase("P").Round(time.Millisecond)))

	// on, then B
	t0 = time.Now()
	runCLI(t, bin, "on")
	report = append(report, fmt.Sprintf("on %v", time.Since(t0).Round(time.Millisecond)))
	if st = runCLI(t, bin, "status"); checkStatusSessions(st, socks) != nil {
		t.Fatalf("after on not all four recording:\n%s", st)
	}
	report = append(report, fmt.Sprintf("phase B %v", phase("B").Round(time.Millisecond)))

	for _, s := range sessions {
		s.screen.exit(t)
	}
	for sock, h := range servers {
		if r, _ := windows.WaitForSingleObject(h, 30000); r != windows.WAIT_OBJECT_0 {
			t.Fatalf("session server of %s did not exit within 30 s", filepath.Base(sock))
		}
	}

	// reopen the encrypted database
	db, err := store.Open(filepath.Join(home, ".pentrail", "pentrail.db"), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	infos, err := db.ListSessions()
	if err != nil || len(infos) != 4 {
		t.Fatalf("sessions %+v %v", infos, err)
	}
	byID := map[int64]store.SessionInfo{}
	var ids []int64
	for _, in := range infos {
		byID[in.ID] = in
		ids = append(ids, in.ID)
	}
	sortInt64(ids) // started one after another: ids in start order
	for i, s := range sessions {
		in := byID[ids[i]]
		if !strings.EqualFold(in.Shell, s.wantShell) {
			t.Fatalf("session %d shell %q, want %q", in.ID, in.Shell, s.wantShell)
		}
		raw, missing, err := db.ReadRange(in.ID, 0, in.RawBytes)
		if err != nil || missing != 0 {
			t.Fatalf("session %d raw: missing %d err %v", in.ID, missing, err)
		}
		if strings.Contains(string(raw), token) || strings.Contains(flatVisible(string(raw)), token) {
			t.Fatalf("session %d: the private token of the paused phase is in the database", in.ID)
		}
		flat := flatVisible(string(raw))
		for j := range sessions {
			if j != i && strings.Contains(flat, fmt.Sprintf("S%d-", j+1)) {
				t.Fatalf("session %d holds lines of session %d", in.ID, j+1)
			}
		}
		for _, ph := range []string{"A", "B"} {
			if n, first := orderedMissing(flat, s.ph[ph].lines); n != 0 {
				t.Fatalf("session %d (%s) phase %s: %d of %d lines missing or out of order, first %q", in.ID, s.wantShell, ph, n, len(s.ph[ph].lines), first)
			}
		}
		lFound := strings.Count(flat, fmt.Sprintf("S%d-L-", i+1))
		cmds, err := db.ListCommands(in.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cmds {
			if strings.Contains(c.Command, token) || c.Command == command(s, "P") {
				t.Fatalf("session %d: the command typed while paused was recorded: %q", in.ID, c.Command)
			}
		}
		for _, ph := range []string{"A", "B"} {
			want := command(s, ph)
			var found *store.CommandInfo
			for k := range cmds {
				if cmds[k].Command == want {
					found = &cmds[k]
				}
			}
			if found == nil {
				t.Fatalf("session %d (%s): command %q not recorded; commands %+v", in.ID, s.wantShell, want, cmds)
			}
			b, miss, err := db.ReadRange(in.ID, found.OutStartOff, found.OutEndOff)
			lines := s.ph[ph].lines
			if err != nil || miss != 0 || !strings.Contains(flatVisible(string(b)), lines[0]) || !strings.Contains(flatVisible(string(b)), lines[len(lines)-1]) {
				t.Fatalf("session %d phase %s: first/END line not in the command's output range %d..%d (missing %d, err %v)", in.ID, ph, found.OutStartOff, found.OutEndOff, miss, err)
			}
		}
		report = append(report, fmt.Sprintf("session %d %s: raw %d B, commands %d, A %d/%d and B %d/%d lines, L lines recorded %d (not asserted), private token absent",
			in.ID, s.wantShell, in.RawBytes, len(cmds), len(s.ph["A"].lines), len(s.ph["A"].lines), len(s.ph["B"].lines), len(s.ph["B"].lines), lFound))
	}
	t.Logf("MULTI_TERMINALS_PASS\n  %s", strings.Join(report, "\n  "))
}

// Limits of one L producer: it never runs unbounded, even if the test that
// started it died before creating its stop file.
const (
	producerMaxLines = 120000
	producerMaxRun   = 2 * time.Minute
)

// TestMultiTerminalProducer is the L-phase producer of
// TestWindowsFourTerminalsUnderOutput, started inside a test terminal as
// `<private copy> -test.run=TestMultiTerminalProducer <n> <ctl dir>`.
// Without those two arguments (any normal test run) it skips. It prints
// paced lines S<n>-L-<i>-<hex> (25 lines, then a 25 ms pause, checking the
// stop file), ends at ctl/stop-<n> or at its limit, prints S<n>-L-END and
// writes ctl/done-<n> with the reason ("stop" or "limit").
func TestMultiTerminalProducer(t *testing.T) {
	a := flag.Args()
	if len(a) != 2 {
		t.Skip("helper of TestWindowsFourTerminalsUnderOutput; runs only when started by it")
	}
	n, ctl := a[0], a[1]
	if _, err := strconv.Atoi(n); err != nil {
		t.Fatalf("session number %q", n)
	}
	w := bufio.NewWriterSize(os.Stdout, 8<<10)
	why := "limit"
	deadline := time.Now().Add(producerMaxRun)
	for i := 0; i < producerMaxLines && time.Now().Before(deadline); i++ {
		if i%25 == 0 {
			w.Flush()
			if _, err := os.Stat(filepath.Join(ctl, "stop-"+n)); err == nil {
				why = "stop"
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		h := sha256.Sum256([]byte(n + "/" + strconv.Itoa(i)))
		fmt.Fprintf(w, "S%s-L-%06d-%x\r\n", n, i, h[:20])
	}
	fmt.Fprintf(w, "S%s-L-END\r\n", n)
	w.Flush()
	if err := os.WriteFile(filepath.Join(ctl, "done-"+n), []byte(why), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sortInt64(v []int64) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
