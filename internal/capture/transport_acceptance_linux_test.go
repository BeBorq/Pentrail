//go:build linux

package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// Two concurrent writers use a short write lock and an independent journal
// to make the intended stdout/stderr interleaving unambiguous. The subject
// never reads that journal. Only synthetic bytes are written in private HOME.
func TestLinuxTransportProducer(t *testing.T) {
	idx := -1
	for i, a := range os.Args {
		if a == "--" {
			idx = i
			break
		}
	}
	if idx < 0 || len(os.Args) != idx+2 {
		t.Skip("private producer helper")
	}
	ctl := os.Args[idx+1]
	old, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		os.Exit(2)
	}
	muted := *old
	muted.Lflag &^= unix.ECHO | unix.ECHONL
	if unix.IoctlSetTermios(0, unix.TCSETS, &muted) != nil {
		os.Exit(3)
	}
	journal, err := os.OpenFile(filepath.Join(ctl, "journal"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(4)
	}
	writeFile := func(name, value string) {
		path := filepath.Join(ctl, name)
		if os.WriteFile(path+".new", []byte(value), 0600) != nil || os.Rename(path+".new", path) != nil {
			os.Exit(5)
		}
	}
	fmt.Printf("TRDATA_BEGIN_%d\n", 20+22)
	until := time.Now().Add(4 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(ctl, "release")); err == nil {
			break
		}
		if time.Now().After(until) {
			os.Exit(6)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for channel, file := range []*os.File{os.Stdout, os.Stderr} {
		wg.Add(1)
		go func(channel int, file *os.File) {
			defer wg.Done()
			for n := 1; n <= 1024; n++ {
				line := []byte(fmt.Sprintf("TRCHAN%d_%06d_%s\n", channel, n, strings.Repeat("abcdefghijklmnop", 255)))
				mu.Lock()
				if count, err := journal.Write(line); err != nil || count != len(line) {
					os.Exit(7)
				}
				if count, err := file.Write(line); err != nil || count != len(line) {
					os.Exit(8)
				}
				mu.Unlock()
				writeFile(fmt.Sprintf("progress-%d", channel), strconv.Itoa(n))
			}
		}(channel, file)
	}
	wg.Wait()
	if journal.Close() != nil {
		os.Exit(9)
	}
	writeFile("data-done", "ok")
	// The keystroke selecting the new pacing client is consumed with echo
	// disabled, so it cannot contaminate the independently journalled bytes.
	input := make([]byte, 1)
	if n, err := os.Stdin.Read(input); err != nil || n != 1 || input[0] != '\n' {
		os.Exit(10)
	}
	if unix.IoctlSetTermios(0, unix.TCSETS, old) != nil {
		os.Exit(11)
	}
	fmt.Printf("TRDATA_END_%d\n", 30+43)
	os.Exit(0)
}

func TestLinuxTransportActualClientTakeoverResizeInterrupt(t *testing.T) {
	src := os.Getenv("PENTRAIL_TEST_BINARY")
	if src == "" || os.Getenv("PENTRAIL_TRANSPORT_ACCEPTANCE") != "1" {
		t.Skip("set actual encrypted package and transport opt-in")
	}
	if !store.Encrypted() {
		t.Fatal("SQLCipher required")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	work, err := os.MkdirTemp("", "pentrail-linux-transport-")
	if err != nil {
		t.Fatal(err)
	}
	bin := luCopy(t, src, luSHA(t, src), filepath.Join(work, "bin"))
	helper := luCopy(t, os.Args[0], luSHA(t, os.Args[0]), filepath.Join(work, "helper"))
	home, ctl := filepath.Join(work, "home"), filepath.Join(work, "control")
	for _, path := range []string{home, ctl} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("private directory")
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("PS1='UP_PROMPT> '\nHISTFILE=/dev/null\nHISTCONTROL=\nHISTIGNORE=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const key = "synthetic-transport-key"
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TERM=dumb", "LANG=C", "SHELL=" + bash, "PENTRAIL_PASSPHRASE=" + key}
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	var clients []*luClient
	var server *luServer
	var sock string
	t.Cleanup(func() {
		os.WriteFile(filepath.Join(ctl, "release"), nil, 0600)
		for _, c := range clients {
			io.WriteString(c.f, "\n\x03exit\n")
			c.end()
		}
		gone := server != nil && !server.alive()
		if server != nil && server.alive() {
			a := luStart(bin, env, "attach", "--db", db, "--sock", sock)
			if a != nil {
				clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
				if a.soon(clean, 0, "Detach with Ctrl-\\.") && a.raw(clean) {
					m := a.mark()
					io.WriteString(a.f, "\x03")
					a.soon(clean, m, "UP_PROMPT> ")
					io.WriteString(a.f, "exit\n")
				}
				stop()
				a.end()
			}
			gone = server.waitGone(25 * time.Second)
		}
		if gone {
			os.RemoveAll(work)
		} else {
			t.Logf("retaining private work %s; no unidentified server signal", work)
		}
	})
	first := luMust(t, luStart(bin, env, "start", "--db", db, "--shell", bash))
	clients = append(clients, first)
	sock = luWaitSocket(t, ctx, filepath.Join(home, ".pentrail", "run"), nil)
	server = luIdentify(t, sock, bin)
	first.waitFor(t, ctx, 0, "UP_PROMPT> ")
	first.waitRaw(t, ctx)
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	producer := fmt.Sprintf("%s %s -- %s", quote(helper), quote("-test.run=^TestLinuxTransportProducer$"), quote(ctl))
	mark := first.mark()
	io.WriteString(first.f, producer+"\n")
	first.waitFor(t, ctx, mark, "TRDATA_BEGIN_42\r\n")
	// A pidfd plus matching /proc start time and image prevents PID reuse
	// from redirecting the stop to a different process. It is our Cmd child.
	start, image, ok := luProc(first.cmd.Process.Pid)
	if !ok || image != bin {
		t.Fatal("client identity is not the private executable")
	}
	pidfd, err := unix.PidfdOpen(first.cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	checkStart, checkImage, ok := luProc(first.cmd.Process.Pid)
	if !ok || checkStart != start || checkImage != image {
		t.Fatal("client identity changed before stop")
	}
	defer unix.PidfdSendSignal(pidfd, unix.SIGCONT, nil, 0)
	if err := unix.PidfdSendSignal(pidfd, unix.SIGSTOP, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctl, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	progress := func() int {
		total := 0
		for i := 0; i < 2; i++ {
			b, _ := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("progress-%d", i)))
			n, _ := strconv.Atoi(string(b))
			total += n
		}
		return total
	}
	until := time.Now().Add(40 * time.Second)
	last, stable := progress(), time.Now()
	for {
		n := progress()
		if n != last {
			last = n
			stable = time.Now()
		}
		if n > 2 && n < 2048 && time.Since(stable) > 750*time.Millisecond {
			break
		}
		if _, err := os.Stat(filepath.Join(ctl, "data-done")); err == nil {
			t.Fatal("output was not backpressured by the stopped pacer")
		}
		if time.Now().After(until) {
			t.Fatalf("no bounded stalled-pacer condition; progress=%d", n)
		}
		time.Sleep(25 * time.Millisecond)
	}
	server.mustLive(t, "while original client is stopped and producer is blocked")
	state, err := sessionio.RequestControl(sock, "status")
	if err != nil || !state.Recording || state.CaptureError != "" {
		t.Fatalf("control while pacer stopped: %+v %v", state, err)
	}
	t.Logf("TRANSPORT stopped original client pid=%d; blocked after %d/2048 journalled rows; control replied", first.cmd.Process.Pid, last)
	attach := func() *luClient {
		t.Helper()
		c := luMust(t, luStart(bin, env, "attach", "--db", db, "--sock", sock))
		clients = append(clients, c)
		c.waitFor(t, ctx, 0, "Detach with Ctrl-\\.")
		c.waitRaw(t, ctx)
		server.mustLive(t, "after attaching")
		return c
	}
	current := attach()
	t0 := time.Now()
	io.WriteString(current.f, "\n")
	current.waitFor(t, ctx, 0, "TRDATA_END_73\r\n")
	current.waitFor(t, ctx, 0, "UP_PROMPT> ")
	takeoverTime := time.Since(t0)
	if b, err := os.ReadFile(filepath.Join(ctl, "data-done")); err != nil || string(b) != "ok" {
		t.Fatal("producer did not complete")
	}
	// Kill the old stopped client only, never its surviving session owner.
	first.end()
	server.mustLive(t, "after killing the old client")
	t.Logf("TRANSPORT takeover completed producer in %v; old client killed, same server alive", takeoverTime.Round(time.Millisecond))
	sizeCommand := "printf 'TR_SIZE_%s\\n' \"$(stty size)\""
	mark = current.mark()
	split := len(sizeCommand) / 2
	io.WriteString(current.f, sizeCommand[:split])
	if err := pty.Setsize(current.f, &pty.Winsize{Rows: 37, Cols: 103}); err != nil {
		t.Fatal(err)
	}
	// Observe delivery on this identified session's shell PTY before sending
	// the rest of the unfinished command; a fixed sleep would race SIGWINCH.
	if state.RootPID <= 0 {
		t.Fatal("session did not identify its shell")
	}
	_, shellImage, shellOK := luProc(state.RootPID)
	if !shellOK || shellImage != bash {
		t.Fatal("session shell identity mismatch")
	}
	ttyFD, err := unix.Open(fmt.Sprintf("/proc/%d/fd/0", state.RootPID), unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if ttyFD >= 0 {
			unix.Close(ttyFD)
		}
	}()
	resizeUntil := time.Now().Add(10 * time.Second)
	for {
		ws, err := unix.IoctlGetWinsize(ttyFD, unix.TIOCGWINSZ)
		if err != nil {
			t.Fatal(err)
		}
		if ws.Row == 37 && ws.Col == 103 {
			break
		}
		if time.Now().After(resizeUntil) {
			t.Fatalf("resize not delivered before finishing input: %+v", ws)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Retaining a slave descriptor would prevent the session master from
	// observing EOF when the shell exits; the observation must not alter that.
	unix.Close(ttyFD)
	ttyFD = -1
	io.WriteString(current.f, sizeCommand[split:]+"\n")
	current.waitFor(t, ctx, mark, "TR_SIZE_37 103\r\n")
	current.waitFor(t, ctx, mark, "UP_PROMPT> ")
	interruptCommand := "printf 'TR_INTERRUPT_%s\\n' \"$((20+22))\"; sleep 30"
	mark = current.mark()
	io.WriteString(current.f, interruptCommand+"\n")
	current.waitFor(t, ctx, mark, "TR_INTERRUPT_42\r\n")
	interrupted := current.mark()
	t0 = time.Now()
	io.WriteString(current.f, "\x03")
	current.waitFor(t, ctx, interrupted, "UP_PROMPT> ")
	interruptTime := time.Since(t0)
	if interruptTime > 5*time.Second {
		t.Fatalf("Ctrl-C took %v", interruptTime)
	}
	health := map[string]string{}
	for cycle := 0; cycle < 3; cycle++ {
		command := fmt.Sprintf("printf 'TR_ATTACH%d_%%s\\n' \"$((30+12))\"", cycle)
		result := fmt.Sprintf("TR_ATTACH%d_42", cycle)
		current.roundtrip(t, ctx, command, result)
		health[command] = result
		if cycle < 2 {
			io.WriteString(current.f, "\x1c")
			if err := current.wait(ctx); err != nil {
				t.Fatalf("explicit detach: %v", err)
			}
			server.mustLive(t, "after explicit detach")
			current = attach()
		}
	}
	io.WriteString(current.f, "exit\n")
	if err := current.wait(ctx); err != nil {
		t.Fatal(err)
	}
	if !server.waitGone(30 * time.Second) {
		t.Fatal("server did not end normally")
	}
	st, err := store.Open(db, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sessions, err := st.ListSessions()
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions %v %v", sessions, err)
	}
	session := sessions[0]
	health[producer] = "TRDATA_END_73"
	health[sizeCommand] = "TR_SIZE_37 103"
	luCheckSession(t, st, session, health, nil)
	commands, err := st.ListCommands(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	interrupts := 0
	var producerOutput []byte
	for _, command := range commands {
		if command.Command == interruptCommand {
			interrupts++
			if !command.Complete || command.EndReason != "" || command.ExitCode != 130 || command.EndedMs <= command.StartedMs {
				t.Fatalf("interrupt metadata: %+v", command)
			}
		}
		if command.Command == producer {
			var missing int64
			producerOutput, missing, err = st.ReadRange(session.ID, command.OutStartOff, command.OutEndOff)
			if err != nil || missing != 0 {
				t.Fatal("producer range gap")
			}
		}
	}
	if interrupts != 1 {
		t.Fatalf("interrupt command recorded %d times", interrupts)
	}
	begin, end := []byte("TRDATA_BEGIN_42\r\n"), []byte("TRDATA_END_73\r\n")
	if bytes.Count(producerOutput, begin) != 1 || bytes.Count(producerOutput, end) != 1 {
		t.Fatal("producer boundaries missing or duplicated")
	}
	from, to := bytes.Index(producerOutput, begin)+len(begin), bytes.Index(producerOutput, end)
	if to < from {
		t.Fatal("invalid producer bounds")
	}
	journal, err := os.ReadFile(filepath.Join(ctl, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(journal, []byte{'\n'}) != 2048 {
		t.Fatal("independent journal is incomplete")
	}
	want := bytes.ReplaceAll(journal, []byte{'\n'}, []byte{'\r', '\n'})
	got := producerOutput[from:to]
	if !bytes.Equal(got, want) {
		t.Fatalf("interleaved output differs byte-for-byte: got=%d want=%d", len(got), len(want))
	}
	t.Logf("LINUX_TRANSPORT_PASS sha256=%s private_server_pid=%d stop_pacer=true takeover=true client_kill=true attach_cycles=3 resize_while_typing=37x103 ctrl_c_exit=130 journal_exact_bytes=%d stdout_stderr_rows=2048 pending=0 recoveries=0 missing=0 normal_server_exit=true", luSHA(t, src), server.pid, len(want))
}
