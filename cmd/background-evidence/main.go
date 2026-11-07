//go:build linux

// End-to-end UX test; synthetic data only, isolated HOME in the test VM.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BeBorq/Pentrail/internal/redact"
	"github.com/BeBorq/Pentrail/internal/store"
	"github.com/creack/pty"
)

const key = "synthetic-background-key"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func cli(unlock bool, args ...string) string {
	c := exec.Command("/tests/pentrail", args...)
	c.Env = os.Environ()
	if unlock {
		c.Env = append(c.Env, "PENTRAIL_PASSPHRASE="+key)
	}
	b, err := c.CombinedOutput()
	if err != nil {
		log, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".pentrail/run/viewer.log"))
		panic(fmt.Sprintf("%v: %v %s viewer log: %s", args, err, b, log))
	}
	return string(b)
}

type terminal struct {
	cmd *exec.Cmd
	f   *os.File
	mu  sync.Mutex
	b   bytes.Buffer
}

func term(shell string) *terminal {
	c := exec.Command(shell, "-i")
	c.Env = os.Environ()
	f, err := pty.Start(c)
	must(err)
	t := &terminal{cmd: c, f: f}
	go func() {
		b := make([]byte, 8192)
		for {
			n, err := f.Read(b)
			if n > 0 {
				t.mu.Lock()
				t.b.Write(b[:n])
				t.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return t
}
func (t *terminal) wait(s string) {
	until := time.Now().Add(40 * time.Second)
	for {
		t.mu.Lock()
		b := t.b.String()
		t.mu.Unlock()
		if strings.Contains(b, s) {
			return
		}
		if time.Now().After(until) {
			panic("terminal timeout " + s + ": " + b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func (t *terminal) send(s string) { _, err := t.f.WriteString(s); must(err) }
func (t *terminal) exit()         { t.send("exit\n"); must(t.cmd.Wait()); t.f.Close() }
func main() {
	home, err := os.MkdirTemp("", "pt-background-")
	must(err)
	defer os.RemoveAll(home)
	diagnostic := func() {
		paths, _ := filepath.Glob(filepath.Join(home, ".pentrail", "run", "*.log"))
		for _, path := range paths {
			data, _ := os.ReadFile(path)
			fmt.Printf("DIAGNOSTIC %s: %s\n", filepath.Base(path), data)
		}
	}
	defer func() {
		if p := recover(); p != nil {
			diagnostic()
			panic(p)
		}
	}()
	timer := time.AfterFunc(60*time.Second, diagnostic)
	defer timer.Stop()
	os.Setenv("HOME", home)
	os.Setenv("SHELL", "/bin/bash")
	os.Setenv("TERM", "dumb")
	os.Setenv("PATH", filepath.Join(home, ".local/bin")+":/usr/bin:/bin:/usr/sbin:/sbin")
	must(os.WriteFile(filepath.Join(home, ".bashrc"), []byte("PS1='USER_PROMPT> '\nprintf 'USER_RC_LOADED\\n'\n"), 0600))
	cli(false, "setup", "bash")
	cli(true, "on")
	a, b := term("/bin/bash"), term("/bin/bash")
	a.wait("USER_PROMPT>")
	b.wait("USER_PROMPT>")
	for _, t := range []*terminal{a, b} {
		t.mu.Lock()
		s := t.b.String()
		t.mu.Unlock()
		if strings.Contains(s, "pentrail:") || strings.Contains(s, "passphrase:") || strings.Count(s, "USER_RC_LOADED") != 1 {
			panic("startup was visible or rc executed twice: " + s)
		}
	}
	a.send("printf 'BG_%s\\n' FIRST\n")
	b.send("printf 'BG_%s\\n' SECOND\n")
	a.wait("BG_FIRST")
	b.wait("BG_SECOND")
	s := cli(false, "status")
	if strings.Count(s, "recording=true") != 2 {
		panic("expected two active sessions: " + s)
	}
	fmt.Println("BACKGROUND two_new_bash_windows_record=true startup_silent=true user_rc_once=true key_agent_reused=true")
	cli(false, "off")
	a.send("printf 'BG_%s\\n' PAUSED_A\n")
	b.send("printf 'BG_%s\\n' PAUSED_B\n")
	a.wait("BG_PAUSED_A")
	b.wait("BG_PAUSED_B")
	s = cli(false, "status")
	if strings.Count(s, "recording=false") != 2 || !strings.Contains(s, "key_unlocked=false") {
		panic("off failed: " + s)
	}
	c := term("/bin/bash")
	c.wait("USER_PROMPT>")
	c.send("printf 'BG_WRAPPED=%s\\n' \"${PENTRAIL:-no}\"\n")
	c.wait("BG_WRAPPED=no")
	c.exit()
	fmt.Println("BACKGROUND off_pauses_all_existing=true shells_still_work=true new_window_unwrapped=true key_agent_stopped=true")
	cli(true, "on")
	a.send("printf 'BG_%s\\n' RESUMED_A\n")
	b.send("printf 'BG_%s\\n' RESUMED_B\n")
	a.wait("BG_RESUMED_A")
	b.wait("BG_RESUMED_B")
	must(os.WriteFile(filepath.Join(home, ".zshrc"), []byte("PROMPT='ZSH_PROMPT> '\n"), 0600))
	cli(false, "setup", "zsh")
	z := term("/bin/zsh")
	z.wait("ZSH_PROMPT>")
	z.send("printf 'BG_%s\\n' ZSH\n")
	z.wait("BG_ZSH")
	var expected50, commands50 []string
	for _, entry := range []struct {
		name string
		t    *terminal
	}{{"BASH", a}, {"ZSH", z}} {
		for i := 1; i <= 50; i++ {
			expression := fmt.Sprintf("%d*%d+7", i, i)
			value := fmt.Sprint(i*i + 7)
			command := fmt.Sprintf("printf 'L50_%s_%%02d=%%s\\n' %d \"$((%s))\"", entry.name, i, expression)
			if i == 46 {
				value = "żółć"
				command = fmt.Sprintf("printf 'L50_%s_%%02d=%%s\\n' %d 'żółć'", entry.name, i)
			}
			if i == 48 {
				value = "PASSWORD='Linux50Secret'"
				command = fmt.Sprintf("printf 'L50_%s_%%02d=%%s\\n' %d \"PASSWORD='Linux50Secret'\"", entry.name, i)
			}
			expected := fmt.Sprintf("L50_%s_%02d=%s", entry.name, i, value)
			entry.t.send(command + "\n")
			entry.t.wait(expected)
			expected50 = append(expected50, redact.String(expected))
			commands50 = append(commands50, redact.String(command))
			fmt.Printf("FIFTY LIVE shell=%s n=%02d PASS\n", entry.name, i)
		}
	}

	z.exit()
	fmt.Println("BACKGROUND on_resumes_existing=true zsh_autostart=true")
	link := strings.TrimSpace(cli(false, "open", "--no-browser"))
	client := http.Client{Timeout: 3 * time.Second}
	r, err := client.Get(link)
	must(err)
	r.Body.Close()
	if r.StatusCode != 200 {
		panic("viewer unavailable")
	}
	fmt.Println("BACKGROUND viewer_open_on_demand=true authenticated_http_status=200")
	a.exit()
	b.exit()
	cli(false, "off")
	st, err := store.Open(filepath.Join(home, ".pentrail/pentrail.db"), []byte(key))
	must(err)
	defer st.Close()
	ss, err := st.ListSessions()
	must(err)
	if len(ss) != 3 {
		panic(fmt.Sprintf("expected 3 recorded sessions, got %d", len(ss)))
	}
	var recordedCommands []string
	var all bytes.Buffer
	for _, s := range ss {
		raw, missing, err := st.ReadRange(s.ID, 0, s.RawBytes)
		must(err)
		if missing != 0 {
			panic("raw gap")
		}
		cmds, e := st.ListCommands(s.ID)
		must(e)
		for _, c := range cmds {
			recordedCommands = append(recordedCommands, c.Command)
		}
		all.Write(raw)
	}
	for _, marker := range []string{"BG_FIRST", "BG_SECOND", "BG_RESUMED_A", "BG_RESUMED_B", "BG_ZSH"} {
		if !bytes.Contains(all.Bytes(), []byte(marker)) {
			panic("missing recorded marker " + marker)
		}
	}
	for _, private := range []string{"PAUSED_A", "PAUSED_B", key} {
		if bytes.Contains(all.Bytes(), []byte(private)) {
			panic("private data was recorded: " + private)
		}
	}
	for i, want := range expected50 {
		if !bytes.Contains(all.Bytes(), []byte(want)) {
			panic("lost output: " + want)
		}
		found := false
		for _, command := range recordedCommands {
			if command == commands50[i] {
				found = true
				break
			}
		}
		if !found {
			panic("lost command metadata: " + commands50[i])
		}
	}
	if bytes.Contains(all.Bytes(), []byte("Linux50Secret")) {
		panic("Linux secret leaked")
	}
	fmt.Println("FIFTY REOPEN outputs=100/100 commands=100/100 missing=0 unicode=PASS secret_masking=PASS")
	fmt.Println("BACKGROUND encrypted_reopen=true sessions=3 paused_commands_and_output_absent=true resumed_output_present=true missing_bytes=0")
	fmt.Println("BACKGROUND PASS")
}
