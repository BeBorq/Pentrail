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
	"strings"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Four actual CLI sessions, private HOME/database/key, no network. Each shell
// emits a computed BEGIN marker then waits on a private file. Only after all
// four markers arrived is the file created, so launch timing alone cannot
// masquerade as concurrent command execution. Stored command intervals must
// additionally have a nonempty common intersection. Every generated public
// output row must appear exactly once in its own command's complete range.
func TestLinuxFourTerminalsUnderOutput(t *testing.T) {
	src := os.Getenv("PENTRAIL_TEST_BINARY")
	if src == "" || os.Getenv("PENTRAIL_MULTI_TERMINALS") != "1" {
		t.Skip("set PENTRAIL_MULTI_TERMINALS=1 and PENTRAIL_TEST_BINARY")
	}
	if !store.Encrypted() {
		t.Fatal("requires SQLCipher test helper")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash required")
	}
	work, err := os.MkdirTemp("", "pentrail-linux-four-")
	if err != nil {
		t.Fatal(err)
	}
	bin := luCopy(t, src, luSHA(t, src), filepath.Join(work, "bin"))
	home := filepath.Join(work, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("PS1='UP_PROMPT> '\nHISTFILE=/dev/null\nHISTCONTROL=\nHISTIGNORE=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const key = "synthetic-four-linux-key"
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	gate := filepath.Join(work, "release-producers")
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SHELL=" + bash, "TERM=dumb", "LANG=C", "PENTRAIL_PASSPHRASE=" + key}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var clients []*luClient
	servers := map[string]*luServer{}
	unidentified := 0
	t.Cleanup(func() {
		_ = os.WriteFile(gate, []byte("release own synthetic producers\n"), 0600)
		for _, c := range clients {
			_, _ = io.WriteString(c.f, "exit\n")
			c.end()
		}
		gone := true
		for sock, srv := range servers {
			if !srv.alive() {
				continue
			}
			a := luStart(bin, env, "attach", "--db", db, "--sock", sock)
			if a != nil {
				clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
				if a.soon(clean, 0, "Detach with Ctrl-\\.") && a.raw(clean) {
					m := a.mark()
					_, _ = io.WriteString(a.f, "\x03")
					a.soon(clean, m, "UP_PROMPT> ")
					_, _ = io.WriteString(a.f, "exit\n")
				}
				stop()
				a.end()
			}
			if !srv.waitGone(30 * time.Second) {
				gone = false
				t.Logf("private server %d still running; no signal sent", srv.pid)
			}
		}
		if gone && unidentified == 0 {
			os.RemoveAll(work)
		} else {
			t.Logf("private directory retained: %s (unidentified=%d)", work, unidentified)
		}
	})
	known := []string{}
	pids := map[int]bool{}
	for i := 0; i < 4; i++ {
		unidentified++
		c := luMust(t, luStart(bin, env, "start", "--db", db, "--shell", bash))
		clients = append(clients, c)
		sock := luWaitSocket(t, ctx, filepath.Join(home, ".pentrail", "run"), known)
		srv := luIdentify(t, sock, bin)
		servers[sock] = srv
		unidentified--
		if pids[srv.pid] {
			t.Fatal("sessions share a server PID")
		}
		pids[srv.pid] = true
		known = append(known, sock)
		c.waitFor(t, ctx, 0, "UP_PROMPT> ")
		c.waitRaw(t, ctx)
	}
	const rows = 512
	payload := strings.Repeat("abcdefghijklmnop", 8)
	commands := make([]string, 4)
	marks := make([]int, 4)
	quotedGate := "'" + strings.ReplaceAll(gate, "'", "'\\''") + "'"
	for i, c := range clients {
		commands[i] = fmt.Sprintf("printf 'LINUX4_T%d_BEGIN_%%s\\n' \"$((20+22))\"; while [ ! -f %s ]; do sleep 0.02; done; for i in {1..%d}; do printf 'LINUX4_T%d_ROW_%%04d_%s\\n' \"$i\"; done; printf 'LINUX4_T%d_DONE_%%s\\n' \"$((30+43))\"", i, quotedGate, rows, i, payload, i)
		marks[i] = c.mark()
	}
	barrier := make(chan struct{})
	writes := make(chan error, 4)
	for i, c := range clients {
		go func(c *luClient, command string) {
			<-barrier
			n, e := io.WriteString(c.f, command+"\n")
			if e == nil && n != len(command)+1 {
				e = io.ErrShortWrite
			}
			writes <- e
		}(c, commands[i])
	}
	close(barrier)
	for range clients {
		if e := <-writes; e != nil {
			t.Fatal(e)
		}
	}
	for i, c := range clients {
		c.waitFor(t, ctx, marks[i], fmt.Sprintf("LINUX4_T%d_BEGIN_42\r\n", i))
	}
	for _, srv := range servers {
		srv.mustLive(t, "all four foreground commands waiting at the same private gate")
	}
	if e := os.WriteFile(gate, []byte("release\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for i, c := range clients {
		c.waitFor(t, ctx, marks[i], fmt.Sprintf("LINUX4_T%d_DONE_73\r\n", i))
		c.waitFor(t, ctx, marks[i], "UP_PROMPT> ")
	}
	health := make([]string, 4)
	for i, c := range clients {
		health[i] = fmt.Sprintf("printf 'LINUX4_T%d_HEALTH_%%s\\n' \"$((5+6))\"", i)
		c.roundtrip(t, ctx, health[i], fmt.Sprintf("LINUX4_T%d_HEALTH_11", i))
	}
	for _, c := range clients {
		_, _ = io.WriteString(c.f, "exit\n")
	}
	for _, c := range clients {
		if e := c.wait(ctx); e != nil {
			t.Fatal(e)
		}
	}
	for _, srv := range servers {
		if !srv.waitGone(30 * time.Second) {
			t.Fatal("private server did not end normally")
		}
	}
	st, e := store.Open(db, []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	sessions, e := st.ListSessions()
	if e != nil || len(sessions) != 4 {
		t.Fatalf("sessions %v %v", sessions, e)
	}
	seen := [4]bool{}
	latestStart := int64(0)
	earliestEnd := int64(1<<63 - 1)
	for _, s := range sessions {
		cmds, e := st.ListCommands(s.ID)
		if e != nil {
			t.Fatal(e)
		}
		terminal := -1
		var generator store.CommandInfo
		for _, c := range cmds {
			for i, want := range commands {
				if c.Command == want {
					if terminal >= 0 {
						t.Fatal("multiple producer commands in one session")
					}
					terminal = i
					generator = c
				}
			}
		}
		if terminal < 0 || seen[terminal] {
			t.Fatalf("session %d cannot be assigned uniquely", s.ID)
		}
		seen[terminal] = true
		if generator.StartedMs <= 0 || generator.EndedMs <= generator.StartedMs {
			t.Fatalf("invalid producer interval: %+v", generator)
		}
		latestStart = max(latestStart, generator.StartedMs)
		earliestEnd = min(earliestEnd, generator.EndedMs)
		foreign := []string{}
		for i := 0; i < 4; i++ {
			if i != terminal {
				foreign = append(foreign, fmt.Sprintf("LINUX4_T%d_", i))
			}
		}
		luCheckSession(t, st, s, map[string]string{commands[terminal]: fmt.Sprintf("LINUX4_T%d_DONE_73", terminal), health[terminal]: fmt.Sprintf("LINUX4_T%d_HEALTH_11", terminal)}, foreign)
		out, missing, e := st.ReadRange(s.ID, generator.OutStartOff, generator.OutEndOff)
		if e != nil || missing != 0 {
			t.Fatalf("range missing=%d err=%v", missing, e)
		}
		for row := 1; row <= rows; row++ {
			line := []byte(fmt.Sprintf("LINUX4_T%d_ROW_%04d_%s\r\n", terminal, row, payload))
			if count := bytes.Count(out, line); count != 1 {
				t.Fatalf("terminal %d row %d count=%d", terminal, row, count)
			}
		}
	}
	if earliestEnd <= latestStart {
		t.Fatalf("no common recorded execution interval: latest start=%d earliest end=%d", latestStart, earliestEnd)
	}
	t.Logf("LINUX_FOUR_PASS subject_sha256=%s sessions=4 distinct_servers=4 rows=%d/%d common_overlap_ms=%d all_commands_complete=true raw_missing=0 foreign_output_absent=true normal_exit=true", luSHA(t, src), 4*rows, 4*rows, earliestEnd-latestStart)
}
