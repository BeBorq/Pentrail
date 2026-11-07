//go:build linux

package hooks

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// A real interactive PTY: prompt boundaries, history and DEBUG traps differ
// from a noninteractive script or bash -i with piped standard input.
func TestBashPTYCompoundMetadata(t *testing.T) {
	t.Run("default", func(t *testing.T) { bashPTYCompound(t, "") })
	t.Run("existing_debug", func(t *testing.T) { bashPTYCompound(t, "trap 'printf USER_DEBUG' DEBUG\n") })
	t.Run("scalar_prompt_trailing_semicolon", func(t *testing.T) {
		bashPTYCompound(t, `
__user_prompt_one() { printf 'USER_PROMPT_ONE_STATUS=%s\n' "$?"; history -s 'SYNTHETIC_PRIVATE_PROMPT'; }
__user_prompt_two() { printf 'USER_PROMPT_TWO\n'; }
PROMPT_COMMAND='__user_prompt_one; __user_prompt_two;'
PS0='USER_PS0'
`)
	})
	t.Run("prompt_array", func(t *testing.T) {
		bashPTYCompound(t, `
__user_prompt_one() { printf 'USER_PROMPT_ONE_STATUS=%s\n' "$?"; history -s 'SYNTHETIC_PRIVATE_PROMPT'; }
__user_prompt_two() { printf 'USER_PROMPT_TWO\n'; }
PROMPT_COMMAND=(__user_prompt_one __user_prompt_two)
PS0='USER_PS0'
`)
	})
}

func bashPTYCompound(t *testing.T, extra string) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash required")
	}
	home := t.TempDir()
	rc := filepath.Join(home, "rc")
	const prompt = "__PT_TEST_PROMPT__> "
	hook := Bash
	if path := os.Getenv("PENTRAIL_TEST_BASH_HOOK"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hook = string(data)
	}
	setup := "PS1='" + prompt + "'\nPS2='__PT_CONT__> '\nHISTFILE=/dev/null\nHISTCONTROL=\nHISTIGNORE=\n" + extra + "\n" + hook
	if err := os.WriteFile(rc, []byte(setup), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "--noprofile", "--rcfile", rc, "-i")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TERM=dumb", "PENTRAIL=1", "PENTRAIL_TOKEN=synthetic-test-token"}
	f, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	chunks := make(chan []byte, 256)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer close(chunks)
		b := make([]byte, 4096)
		for {
			n, e := f.Read(b)
			if n > 0 {
				chunks <- append([]byte(nil), b[:n]...)
			}
			if e != nil {
				return
			}
		}
	}()
	defer func() {
		_, _ = io.WriteString(f, "exit\n")
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = f.Close()
		<-readDone
	}()
	untilPrompt := func(t *testing.T) []byte {
		t.Helper()
		var out bytes.Buffer
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case b, ok := <-chunks:
				if !ok {
					t.Fatalf("shell ended: %q", out.String())
				}
				out.Write(b)
				if bytes.HasSuffix(out.Bytes(), []byte(prompt)) {
					return out.Bytes()
				}
			case <-timer.C:
				t.Fatalf("prompt timeout: %q", out.String())
			}
		}
	}
	untilPrompt(t)
	cases := []struct{ name, line, want string }{
		{"semicolon", "printf 'FIRST\\n'; printf 'SECOND\\n'", ""},
		{"pipeline", "printf 'PIPE\\n' | cat", ""},
		{"or", "false || printf 'FALLBACK\\n'", ""},
		{"quoted", "printf '%s\\n' 'quoted;semicolon'", ""},
		{"previous_status", "printf 'STATUS=%s\\n' \"$?\"", ""},
		{"false", "false", ""},
		{"previous_failure", "printf 'STATUS=%s\\n' \"$?\"", ""},
		{"regex_capture", "[[ saved =~ (saved) ]]", ""},
		{"regex_preserved", "printf 'MATCH=%s\\n' \"${BASH_REMATCH[1]}\"", ""},
		{"multiline_quote", "printf '%s\\n' 'MULTI\nLINE'", ""},
		{"loop", "for x in a b; do printf '%s\\n' \"$x\"; done", ""},
		{"history_off", "set +o history", ""},
		{"private_import", "history -s 'SYNTHETIC_PRIVATE_STALE'", ""},
		{"history_off_current", "printf 'CURRENT_NO_HISTORY\\n'", ""},
		{"history_on", "set -o history", ""},
		{"ignore_space_setting", "HISTCONTROL=ignorespace", ""},
		{"ignored_current", " printf 'CURRENT_IGNORED\\n'", "printf 'CURRENT_IGNORED\\n'"},
		{"clear_control", "HISTCONTROL=", ""},
		{"ignore_setting", "HISTIGNORE='*CURRENT_FILTERED*'", ""},
		{"filtered_current", "printf 'CURRENT_FILTERED\\n'", ""},
		{"clear_ignore", "HISTIGNORE=", ""},
		{"after_ignore", "printf 'AFTER\\n'; printf 'RESTORED\\n'", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.line
			if _, err := io.WriteString(f, line+"\n"); err != nil {
				t.Fatal(err)
			}
			out := untilPrompt(t)
			prefix := "\x1b]697;synthetic-test-token;CMD;"
			var commands []string
			for _, piece := range strings.Split(string(out), prefix)[1:] {
				end := strings.IndexByte(piece, 7)
				if end < 0 {
					t.Fatal("unterminated marker")
				}
				dec, e := base64.StdEncoding.DecodeString(piece[:end])
				if e != nil {
					t.Fatal(e)
				}
				commands = append(commands, string(dec))
			}
			want := tc.want
			if want == "" {
				want = line
			}
			customDebug := strings.Contains(extra, "trap ")
			if customDebug {
				if len(commands) != 0 || !bytes.Contains(out, []byte("USER_DEBUG")) {
					t.Errorf("existing DEBUG trap replaced: commands=%q output=%q", commands, out)
				}
			} else if len(commands) != 1 || commands[0] != want {
				t.Errorf("index=%q; want %q", commands, want)
			}
			if tc.name != "private_import" && strings.Contains(strings.Join(commands, "\n"), "SYNTHETIC_PRIVATE_STALE") {
				t.Error("stale private history entry substituted for current input")
			}
			if strings.Contains(strings.Join(commands, "\n"), "SYNTHETIC_PRIVATE_PROMPT") {
				t.Error("prompt callback/history import recorded as user input")
			}
			if extra != "" && !customDebug {
				if bytes.Count(out, []byte("USER_PS0")) != 1 || bytes.Count(out, []byte("USER_PROMPT_TWO\r\n")) != 1 {
					t.Errorf("user PS0/prompt callbacks changed: %q", out)
				}
				if tc.name == "false" && !bytes.Contains(out, []byte("USER_PROMPT_ONE_STATUS=1\r\n")) {
					t.Errorf("prompt callback lost command exit status: %q", out)
				}
			}
			if tc.name == "previous_status" && !bytes.Contains(out, []byte("STATUS=0\r\n")) {
				t.Errorf("hook changed previous exit status: %q", out)
			}
			if extra == "" && tc.name == "previous_failure" && !bytes.Contains(out, []byte("STATUS=1\r\n")) {
				t.Errorf("hook changed failed exit status: %q", out)
			}
			if tc.name == "regex_preserved" && !bytes.Contains(out, []byte("MATCH=saved\r\n")) {
				t.Errorf("hook changed BASH_REMATCH: %q", out)
			}
		})
	}
}
