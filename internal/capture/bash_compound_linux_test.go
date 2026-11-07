//go:build linux

package capture

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

// Actual CLI, private HOME and encrypted database. Private history imported
// while paused must not be substituted for a history-excluded resumed input.
func TestLinuxBashCompoundAndPausedHistory(t *testing.T) {
	src := os.Getenv("PENTRAIL_TEST_BINARY")
	if src == "" {
		t.Skip("set PENTRAIL_TEST_BINARY")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash required")
	}
	work, err := os.MkdirTemp("", "pentrail-bash-compound-")
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
	const key = "synthetic-bash-regression-key"
	db := filepath.Join(home, ".pentrail", "pentrail.db")
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SHELL=" + bash, "TERM=dumb", "LANG=C", "PENTRAIL_PASSPHRASE=" + key}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var c *luClient
	var srv *luServer
	var sock string
	t.Cleanup(func() {
		if c != nil {
			_, _ = io.WriteString(c.f, "exit\n")
			c.end()
		}
		if srv != nil && srv.alive() {
			a := luStart(bin, env, "attach", "--db", db, "--sock", sock)
			if a != nil {
				clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
				if a.soon(clean, 0, "Detach with Ctrl-\\.") && a.raw(clean) {
					_, _ = io.WriteString(a.f, "exit\n")
				}
				stop()
				a.end()
			}
		}
		if srv != nil && srv.waitGone(10*time.Second) {
			os.RemoveAll(work)
		} else {
			t.Logf("private test directory retained: %s", work)
		}
	})
	c = luMust(t, luStart(bin, env, "start", "--db", db, "--shell", bash))
	sock = luWaitSocket(t, ctx, filepath.Join(home, ".pentrail", "run"), nil)
	srv = luIdentify(t, sock, bin)
	c.waitFor(t, ctx, 0, "UP_PROMPT> ")
	c.waitRaw(t, ctx)
	run := func(line, result string) {
		t.Helper()
		m := c.mark()
		c.roundtrip(t, ctx, line, result)
		c.waitFor(t, ctx, m, "UP_PROMPT> ")
	}
	want := map[string]string{
		"printf 'LEFT-%s\\n' \"$((2+3))\"; printf 'RIGHT-%s\\n' \"$((3+4))\"": "RIGHT-7",
		"printf 'PIPE-%s\\n' \"$((4+5))\" | cat":                              "PIPE-9",
		"false || printf 'FALLBACK-%s\\n' \"$((5+6))\"":                       "FALLBACK-11",
	}
	for _, line := range []string{"printf 'LEFT-%s\\n' \"$((2+3))\"; printf 'RIGHT-%s\\n' \"$((3+4))\"", "printf 'PIPE-%s\\n' \"$((4+5))\" | cat", "false || printf 'FALLBACK-%s\\n' \"$((5+6))\""} {
		run(line, want[line])
	}
	if s, e := sessionio.RequestControl(sock, "off"); e != nil || s.Recording {
		t.Fatalf("pause: %+v %v", s, e)
	}
	run("history -s 'SYNTHETIC_PAUSED_PRIVATE'; HISTCONTROL=ignorespace; printf 'PAUSED-%s\\n' \"$((6+7))\"", "PAUSED-13")
	if s, e := sessionio.RequestControl(sock, "on"); e != nil || !s.Recording {
		t.Fatalf("resume: %+v %v", s, e)
	}
	run(" printf 'RESUMED-%s\\n' \"$((7+8))\"", "RESUMED-15")
	want["printf 'RESUMED-%s\\n' \"$((7+8))\""] = "RESUMED-15"
	_, _ = io.WriteString(c.f, "exit\n")
	if e := c.wait(ctx); e != nil {
		t.Fatal(e)
	}
	if !srv.waitGone(20 * time.Second) {
		t.Fatal("private server did not end normally")
	}
	st, e := store.Open(db, []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	sessions, e := st.ListSessions()
	if e != nil || len(sessions) != 1 {
		t.Fatalf("sessions %v %v", sessions, e)
	}
	luCheckSession(t, st, sessions[0], want, []string{"SYNTHETIC_PAUSED_PRIVATE", "PAUSED-13"})
	luCheckSession(t, st, sessions[0], map[string]string{
		"printf 'LEFT-%s\\n' \"$((2+3))\"; printf 'RIGHT-%s\\n' \"$((3+4))\"": "LEFT-5",
	}, nil)
	t.Log("BASH_COMPOUND_PASS exact compound metadata, complete output ranges, aggregate exits, paused history absent, resumed history-excluded command correct")
}
