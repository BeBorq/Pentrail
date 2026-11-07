//go:build linux

package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/redact"
	"github.com/BeBorq/Pentrail/internal/store"
)

// The helper emits computed rows, not command echo. Files are a private
// handshake: counters prove progress across both control operations, and a
// random paused-only payload never appears in any command sent to the shell.
func TestLinuxMixedProducer(t *testing.T) {
	idx := -1
	for i, a := range os.Args {
		if a == "--" {
			idx = i
			break
		}
	}
	if idx < 0 || len(os.Args) != idx+3 {
		t.Skip("private producer helper")
	}
	ctl, id := os.Args[idx+1], os.Args[idx+2]
	write := func(name, value string) {
		p := filepath.Join(ctl, name+"-"+id)
		if err := os.WriteFile(p+".new", []byte(value), 0600); err != nil {
			os.Exit(4)
		}
		if err := os.Rename(p+".new", p); err != nil {
			os.Exit(5)
		}
	}
	private := false
	deadline := time.Now().Add(3 * time.Minute)
	for n := 1; time.Now().Before(deadline); n++ {
		if _, err := os.Stat(filepath.Join(ctl, "stop-"+id)); err == nil {
			fmt.Printf("MX4_S%s_LOOP_DONE_%d\n", id, n)
			write("done", "stop")
			os.Exit(0)
		}
		if !private {
			if _, err := os.Stat(filepath.Join(ctl, "private-phase")); err == nil {
				b, err := os.ReadFile(filepath.Join(ctl, "private-data"))
				if err != nil {
					os.Exit(6)
				}
				fmt.Printf("MX4_S%s_PRIVATE_%s\n", id, b)
				write("private-done", "ok")
				private = true
			}
		}
		fmt.Printf("MX4_S%s_L_%06d_%s\n", id, n, strings.Repeat("abcdefghijklmnop", 8))
		write("progress", strconv.Itoa(n))
		time.Sleep(50 * time.Millisecond)
	}
	write("done", "timeout")
	os.Exit(7)
}

func TestLinuxMixedFourTerminalsPauseUnderOutput(t *testing.T) {
	src := os.Getenv("PENTRAIL_TEST_BINARY")
	if src == "" || os.Getenv("PENTRAIL_MULTI_TERMINALS") != "1" {
		t.Skip("set actual encrypted package and opt-in")
	}
	if !store.Encrypted() {
		t.Fatal("SQLCipher required")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Fatal(err)
	}
	work, err := os.MkdirTemp("", "pentrail-linux-mixed-four-")
	if err != nil {
		t.Fatal(err)
	}
	bin := luCopy(t, src, luSHA(t, src), filepath.Join(work, "bin"))
	helper := luCopy(t, os.Args[0], luSHA(t, os.Args[0]), filepath.Join(work, "helper"))
	home, ctl := filepath.Join(work, "home"), filepath.Join(work, "control")
	for _, p := range []string{home, ctl} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{
		".bashrc": "PS1='UP_PROMPT> '\nHISTFILE=/dev/null\nHISTCONTROL=\nHISTIGNORE=\n",
		".zshrc":  "PROMPT='UP_PROMPT> '\nHISTFILE=/dev/null\n",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const key = "synthetic-four-mixed-key"
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TERM=dumb", "LANG=C", "PENTRAIL_PASSPHRASE=" + key}
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cli := func(args ...string) string {
		t.Helper()
		cctx, stop := context.WithTimeout(ctx, 25*time.Second)
		defer stop()
		c := exec.CommandContext(cctx, bin, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v: %v %s", args, err, out)
		}
		return string(out)
	}
	var clients []*luClient
	servers := map[string]*luServer{}
	unidentified := 0
	t.Cleanup(func() {
		for i := 0; i < 4; i++ {
			os.WriteFile(filepath.Join(ctl, fmt.Sprintf("stop-%d", i)), nil, 0600)
		}
		for _, c := range clients {
			io.WriteString(c.f, "exit\n")
			c.end()
		}
		gone := true
		for sock, srv := range servers {
			if !srv.alive() {
				continue
			}
			a := luStart(bin, env, "attach", "--db", db, "--sock", sock)
			if a != nil {
				clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
				if a.soon(clean, 0, "Detach with Ctrl-\\.") && a.raw(clean) {
					m := a.mark()
					io.WriteString(a.f, "\x03")
					a.soon(clean, m, "UP_PROMPT> ")
					io.WriteString(a.f, "exit\n")
				}
				stop()
				a.end()
			}
			if !srv.waitGone(20 * time.Second) {
				gone = false
				t.Logf("private server %d retained; no signal", srv.pid)
			}
		}
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		c := exec.CommandContext(clean, bin, "off")
		c.Env = env
		if out, err := c.CombinedOutput(); err != nil {
			gone = false
			t.Logf("private off cleanup: %v %s", err, out)
		}
		stop()
		if gone && unidentified == 0 {
			os.RemoveAll(work)
		} else {
			t.Logf("retained private work %s", work)
		}
	})
	cli("on", "--db", db)
	known := []string{}
	pids := map[int]bool{}
	for _, shell := range []string{bash, zsh, bash, zsh} {
		unidentified++
		c := luMust(t, luStart(bin, env, "start", "--db", db, "--shell", shell))
		clients = append(clients, c)
		sock := luWaitSocket(t, ctx, filepath.Join(home, ".pentrail", "run"), known)
		srv := luIdentify(t, sock, bin)
		servers[sock] = srv
		unidentified--
		if pids[srv.pid] {
			t.Fatal("shared server PID")
		}
		pids[srv.pid] = true
		known = append(known, sock)
		c.waitFor(t, ctx, 0, "UP_PROMPT> ")
		c.waitRaw(t, ctx)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	const rows = 128
	payload := strings.Repeat("abcdefghijklmnop", 8)
	commands := map[string][]string{}
	phase := func(label string) {
		t.Helper()
		gate := filepath.Join(ctl, "release-"+label)
		marks := make([]int, 4)
		commands[label] = make([]string, 4)
		for i, c := range clients {
			command := fmt.Sprintf("printf 'MX4_S%d_%s_BEGIN_%%s\\n' \"$((20+22))\"; while [ ! -f %s ]; do sleep 0.02; done; for i in {1..%d}; do printf 'MX4_S%d_%s_ROW_%%04d_%s\\n' \"$i\"; done; printf 'MX4_S%d_%s_END_%%s\\n' \"$((30+43))\"", i, label, quote(gate), rows, i, label, payload, i, label)
			commands[label][i] = command
			marks[i] = c.mark()
			if _, err := io.WriteString(c.f, command+"\n"); err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range clients {
			c.waitFor(t, ctx, marks[i], fmt.Sprintf("MX4_S%d_%s_BEGIN_42\r\n", i, label))
		}
		if err := os.WriteFile(gate, nil, 0600); err != nil {
			t.Fatal(err)
		}
		for i, c := range clients {
			c.waitFor(t, ctx, marks[i], fmt.Sprintf("MX4_S%d_%s_END_73\r\n", i, label))
			c.waitFor(t, ctx, marks[i], "UP_PROMPT> ")
		}
	}
	phase("A")
	progress := func(i int) int {
		b, _ := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("progress-%d", i)))
		n, _ := strconv.Atoi(string(b))
		return n
	}
	advance := func(before []int, label string) {
		t.Helper()
		until := time.Now().Add(15 * time.Second)
		for i, n := range before {
			if b, e := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("done-%d", i))); e == nil {
				t.Fatalf("producer%d already ended %s: %s", i, label, b)
			}
			for progress(i) <= n {
				if time.Now().After(until) {
					t.Fatalf("producer%d made no progress %s", i, label)
				}
				if b, e := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("done-%d", i))); e == nil {
					t.Fatalf("producer%d ended %s: %s", i, label, b)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if b, e := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("done-%d", i))); e == nil {
				t.Fatalf("producer%d ended after progress %s: %s", i, label, b)
			}
		}
	}
	counts := func() []int {
		out := make([]int, 4)
		for i := range out {
			out[i] = progress(i)
		}
		return out
	}
	for i, c := range clients {
		m := c.mark()
		command := fmt.Sprintf("%s %s -- %s %d", quote(helper), quote("-test.run=^TestLinuxMixedProducer$"), quote(ctl), i)
		io.WriteString(c.f, command+"\n")
		c.waitFor(t, ctx, m, fmt.Sprintf("MX4_S%d_L_000001_", i))
	}
	advance(counts(), "before off")
	beforeOff := counts()
	t0 := time.Now()
	cli("off")
	offTime := time.Since(t0)
	advance(beforeOff, "across off")
	status := cli("status")
	if strings.Count(status, "recording=false") != 4 || !strings.Contains(status, "key_unlocked=false") {
		t.Fatalf("not all paused: %s", status)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	private := "ONLYPAUSED" + hex.EncodeToString(random)
	// An absence must prove pause, rather than accidental masking of the
	// supposedly public random marker. Exercise its complete recognizer context.
	for i := range clients {
		var stream redact.Stream
		stream.Feed([]byte(fmt.Sprintf("MX4_S%d_L_000100_%s\r\n", i, payload)))
		line := []byte(fmt.Sprintf("MX4_S%d_PRIVATE_%s\r\n", i, private))
		out := append(stream.Feed(line), stream.Finish()...)
		if !bytes.Equal(out, line) {
			t.Fatal("paused marker would be masked even while recording; invalid absence oracle")
		}
	}
	if err := os.WriteFile(filepath.Join(ctl, "private-data"), []byte(private), 0600); err != nil {
		t.Fatal(err)
	}
	marks := make([]int, 4)
	for i, c := range clients {
		marks[i] = c.mark()
	}
	if err := os.WriteFile(filepath.Join(ctl, "private-phase"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for i, c := range clients {
		c.waitFor(t, ctx, marks[i], fmt.Sprintf("MX4_S%d_PRIVATE_%s\r\n", i, private))
	}
	advance(counts(), "while paused after private output")
	beforeOn := counts()
	t0 = time.Now()
	cli("on", "--db", db)
	onTime := time.Since(t0)
	advance(beforeOn, "across on")
	status = cli("status")
	if strings.Count(status, "recording=true") != 4 || !strings.Contains(status, "key_unlocked=true") {
		t.Fatalf("not all resumed: %s", status)
	}
	stopProducer := func(i int) {
		t.Helper()
		m := clients[i].mark()
		if err := os.WriteFile(filepath.Join(ctl, fmt.Sprintf("stop-%d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
		clients[i].waitFor(t, ctx, m, fmt.Sprintf("MX4_S%d_LOOP_DONE_", i))
		clients[i].waitFor(t, ctx, m, "UP_PROMPT> ")
		b, err := os.ReadFile(filepath.Join(ctl, fmt.Sprintf("done-%d", i)))
		if err != nil || string(b) != "stop" {
			t.Fatalf("producer%d termination %s %v", i, b, err)
		}
	}
	stopProducer(3)
	beforeProbe := counts()[:3]
	t0 = time.Now()
	clients[3].roundtrip(t, ctx, "printf 'MX4_PROBE_%s\\n' \"$((5+6))\"", "MX4_PROBE_11")
	probeTime := time.Since(t0)
	advance(beforeProbe, "across foreground probe")
	for i := 0; i < 3; i++ {
		stopProducer(i)
	}
	phase("B")
	cli("off")
	for _, c := range clients {
		io.WriteString(c.f, "exit\n")
	}
	for _, c := range clients {
		if err := c.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, srv := range servers {
		if !srv.waitGone(20 * time.Second) {
			t.Fatal("private server did not end normally")
		}
	}
	st, err := store.Open(db, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sessions, err := st.ListSessions()
	if err != nil || len(sessions) != 4 {
		t.Fatalf("sessions %v %v", sessions, err)
	}
	seen := [4]bool{}
	shellCounts := map[string]int{}
	for _, s := range sessions {
		shellCounts[filepath.Base(s.Shell)]++
		cmds, err := st.ListCommands(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		terminal := -1
		for _, c := range cmds {
			for i, text := range commands["A"] {
				if c.Command == text {
					if terminal >= 0 {
						t.Fatal("duplicate A command")
					}
					terminal = i
				}
			}
		}
		if terminal < 0 || seen[terminal] {
			t.Fatalf("session%d not unique", s.ID)
		}
		seen[terminal] = true
		want := map[string]string{}
		for _, ph := range []string{"A", "B"} {
			want[commands[ph][terminal]] = fmt.Sprintf("MX4_S%d_%s_END_73", terminal, ph)
		}
		foreign := []string{private}
		for i := 0; i < 4; i++ {
			if i != terminal {
				foreign = append(foreign, fmt.Sprintf("MX4_S%d_", i))
			}
		}
		luCheckSession(t, st, s, want, foreign)
		raw, missing, err := st.ReadRange(s.ID, 0, s.RawBytes)
		if err != nil || missing != 0 {
			t.Fatal("raw gap")
		}
		for _, ph := range []string{"A", "B"} {
			var commandOutput []byte
			for _, command := range cmds {
				if command.Command == commands[ph][terminal] {
					var miss int64
					commandOutput, miss, err = st.ReadRange(s.ID, command.OutStartOff, command.OutEndOff)
					if err != nil || miss != 0 {
						t.Fatal("command output range has a gap")
					}
				}
			}
			for n := 1; n <= rows; n++ {
				line := []byte(fmt.Sprintf("MX4_S%d_%s_ROW_%04d_%s\r\n", terminal, ph, n, payload))
				if bytes.Count(raw, line) != 1 || bytes.Count(commandOutput, line) != 1 {
					t.Fatalf("session%d phase%s row%d not exactly once", s.ID, ph, n)
				}
			}
		}
	}
	if shellCounts["bash"] != 2 || shellCounts["zsh"] != 2 {
		t.Fatalf("shell mix %v", shellCounts)
	}
	t.Logf("LINUX_MIXED_PAUSE_PASS sha256=%s bash=2 zsh=2 distinct_servers=4 public_rows=%d/%d off_on_across_live_producers=4/4 paused_payload_absent=true normal_exit=true raw_missing=0 off=%v on=%v echo_with_three_producers=%v", luSHA(t, src), 8*rows, 8*rows, offTime.Round(time.Millisecond), onTime.Round(time.Millisecond), probeTime.Round(time.Millisecond))
}
