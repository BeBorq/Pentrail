//go:build windows

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testScreen struct {
	p    *windowsPTY
	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
}

func openScreen(t *testing.T, shell string, args []string) *testScreen {
	t.Helper()
	p, e := startPTY(shell, args, os.Environ())
	if e != nil {
		t.Fatal(e)
	}
	s := &testScreen{p: p, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		b := make([]byte, 16384)
		for {
			n, e := p.Read(b)
			if n > 0 {
				s.mu.Lock()
				s.out.Write(b[:n])
				s.mu.Unlock()
				if bytes.Contains(b[:n], []byte("\x1b[6n")) {
					p.Write([]byte("\x1b[1;1R"))
				}
			}
			if e != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		p.Kill()
		select {
		case <-s.done:
		case <-time.After(3 * time.Second):
		}
		p.Close()
	})
	return s
}
func (s *testScreen) text() string { s.mu.Lock(); defer s.mu.Unlock(); return s.out.String() }
func (s *testScreen) send(t *testing.T, v string) {
	t.Helper()
	if _, e := s.p.Write([]byte(v + "\r")); e != nil {
		t.Fatal(e)
	}
}
func (s *testScreen) wait(t *testing.T, v string) {
	t.Helper()
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		if strings.Contains(s.text(), v) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("waiting for %q: %q", v, s.text())
}
func (s *testScreen) exit(t *testing.T) {
	t.Helper()
	s.send(t, "exit")
	select {
	case <-s.done:
	case <-time.After(20 * time.Second):
		t.Fatalf("shell did not exit: %q", s.text())
	}
	code, e := s.p.Wait()
	if e != nil || code != 0 {
		t.Fatal(code, e)
	}
}
func TestWindowsAutomaticWorkflow(t *testing.T) {
	bin := os.Getenv("PENTRAIL_TEST_BINARY")
	if bin == "" {
		t.Skip("set PENTRAIL_TEST_BINARY to the SQLCipher CLI")
	}
	bin = filepath.Clean(bin)
	if !store.Encrypted() {
		t.Skip("encrypted workflow requires sqlcipher")
	}
	home := filepath.Join(t.TempDir(), "profile żółć with spaces")
	if e := os.MkdirAll(home, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv("PENTRAIL", "")
	t.Setenv("PENTRAIL_PASSPHRASE", "")
	t.Setenv("PENTRAIL_DB", "")
	const key = "synthetic-windows-test-key"
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(home, ".pentrail/run/*.pid"))
		for _, path := range paths {
			b, _ := os.ReadFile(path)
			id, e := strconv.Atoi(string(b))
			if e == nil {
				h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(id))
				if e == nil {
					buf := make([]uint16, 32768)
					size := uint32(len(buf))
					if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
						path := windows.UTF16ToString(buf[:size])
						if strings.EqualFold(path, bin) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(filepath.Join(home, "Local", "Pentrail"))) {
							windows.TerminateProcess(h, 0)
							windows.WaitForSingleObject(h, 10000)
						}
					}
					windows.CloseHandle(h)
				}
			}
		}
	})
	cli := func(unlock bool, args ...string) string {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Env = os.Environ()
		if unlock {
			c.Env = append(c.Env, "PENTRAIL_PASSPHRASE="+key)
		}
		b, e := c.CombinedOutput()
		if e != nil {
			logs, _ := filepath.Glob(filepath.Join(home, ".pentrail/run/*.log"))
			for _, p := range logs {
				v, _ := os.ReadFile(p)
				t.Logf("log %s: %s", p, v)
			}
			t.Fatalf("%v: %v %s", args, e, b)
		}
		return string(b)
	}
	profiles := map[string]string{}
	for _, shell := range []string{"powershell", "pwsh"} {
		path := filepath.Join(home, shell+"-profile.ps1")
		if e := os.WriteFile(path, []byte("Write-Output 'PROFILE_READY_"+shell+"'\n"), 0600); e != nil {
			t.Fatal(e)
		}
		cli(false, "setup", shell, "--profile", path)
		cli(false, "setup", shell, "--profile", path)
		data, _ := os.ReadFile(path)
		if bytes.Count(data, []byte("# >>> pentrail automatic capture >>>")) != 1 {
			t.Fatal("setup duplicated profile block")
		}
		profiles[shell] = path
	}
	rk := fmt.Sprintf(`Software\PentrailTest-%d`, time.Now().UnixNano())
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, rk) })
	cli(false, "setup", "cmd", "--registry-key", rk)
	t.Cleanup(func() { c := exec.Command(bin, "off"); c.Env = os.Environ(); c.Run() })
	cli(true, "on")
	var screens []*testScreen
	for _, name := range []string{"powershell", "pwsh"} {
		shell, e := exec.LookPath(name + ".exe")
		if e != nil {
			t.Fatal(e)
		}
		s := openScreen(t, shell, []string{"-NoLogo", "-NoProfile"})
		s.send(t, ". '"+strings.ReplaceAll(profiles[name], "'", "''")+"'")
		s.wait(t, "PROFILE_READY_"+name)
		s.wait(t, ";A\a")
		if strings.Count(s.text(), "PROFILE_READY_"+name) != 1 || strings.Contains(s.text(), "pentrail: attached") || strings.Contains(s.text(), "passphrase:") {
			t.Fatalf("not silent/rc duplicated: %q", s.text())
		}
		s.send(t, "Write-Output ('WIN_' + '"+name+"_FIRST')")
		s.wait(t, "WIN_"+name+"_FIRST")
		screens = append(screens, s)
	}
	cmd, e := exec.LookPath("cmd.exe")
	if e != nil {
		t.Fatal(e)
	}
	script := filepath.Join(home, ".pentrail/cmd-autorun.cmd")
	c := openScreen(t, cmd, []string{"/D", "/K", `call "` + script + `"`})
	c.wait(t, ";A\a")
	c.send(t, "echo WIN_CMD_FIRST")
	c.wait(t, "WIN_CMD_FIRST")
	screens = append(screens, c)
	status := cli(false, "status")
	if strings.Count(status, "recording=true") != 3 {
		t.Fatal(status)
	}
	t.Log("AUTOSTART powershell_5=true powershell_7=true cmd=true silent=true user_profiles_once=true")
	for i, screen := range screens {
		line := `Write-Output 'PASSWORD=WindowSecret42'`
		if i == 2 {
			line = "echo PASSWORD=WindowSecret42"
		}
		screen.send(t, line)
		screen.wait(t, "WindowSecret42")
	}

	cli(false, "off")
	for i, s := range screens {
		line := fmt.Sprintf("Write-Output ('WIN_' + 'PRIVATE_%d')", i)
		if i == 2 {
			line = fmt.Sprintf("echo WIN_PRIVATE_%d", i)
		}
		s.send(t, line)
		s.wait(t, fmt.Sprintf("WIN_PRIVATE_%d", i))
	}
	status = cli(false, "status")
	if strings.Count(status, "recording=false") != 3 || !strings.Contains(status, "key_unlocked=false") {
		t.Fatal(status)
	}

	offShell, _ := exec.LookPath("powershell.exe")
	offWindow := openScreen(t, offShell, []string{"-NoLogo", "-NoProfile"})
	offWindow.send(t, ". '"+strings.ReplaceAll(profiles["powershell"], "'", "''")+"'")
	offWindow.wait(t, "PROFILE_READY_powershell")
	offWindow.send(t, "Write-Output ('WIN_' + 'OFF_NEW_WINDOW')")
	offWindow.wait(t, "WIN_OFF_NEW_WINDOW")
	offWindow.exit(t)
	offCMD := openScreen(t, cmd, []string{"/D", "/K", `call "` + script + `"`})
	offCMD.send(t, "echo OFF_NEW_CMD")
	offCMD.wait(t, "OFF_NEW_CMD")
	offCMD.exit(t)
	if strings.Count(cli(false, "status"), "recording=false") != 3 {
		t.Fatal("off opened a new recording")
	}
	t.Log("OFF all_sessions_paused=true shells_work=true new_windows_not_recorded=true key_agent_stopped=true")

	cli(true, "on")
	for i, s := range screens {
		line := fmt.Sprintf("Write-Output ('WIN_' + 'RESUMED_%d')", i)
		if i == 2 {
			line = fmt.Sprintf("echo WIN_RESUMED_%d", i)
		}
		s.send(t, line)
		s.wait(t, fmt.Sprintf("WIN_RESUMED_%d", i))
	}
	link := strings.TrimSpace(cli(false, "open", "--no-browser"))
	client := http.Client{Timeout: 3 * time.Second}
	r, e := client.Get(link)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}

	batch := openScreen(t, cmd, []string{"/D", "/C", `call "` + script + `" & echo BATCH_DONE`})
	batch.wait(t, "BATCH_DONE")
	select {
	case <-batch.done:
	case <-time.After(10 * time.Second):
		t.Fatal("CMD /C unexpectedly wrapped")
	}
	psBatch := openScreen(t, offShell, []string{"-NoLogo", "-NoProfile", "-Command", ". '" + strings.ReplaceAll(profiles["powershell"], "'", "''") + "'; Write-Output 'PS_BATCH_DONE'"})
	psBatch.wait(t, "PS_BATCH_DONE")
	select {
	case <-psBatch.done:
	case <-time.After(10 * time.Second):
		t.Fatal("PowerShell -Command unexpectedly wrapped")
	}
	t.Log("VIEWER authenticated_http=200 noninteractive_scripts_not_wrapped=true unicode_paths=true")
	u, _ := url.Parse(link)
	u.Path = "/api/raw"
	q := u.Query()
	q.Set("session", "1")
	q.Set("limit", "1048576")
	u.RawQuery = q.Encode()
	r, e = client.Get(u.String())
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || bytes.Contains(body, []byte("WindowSecret42")) || !bytes.Contains(body, []byte("PASSWORD=**************")) {
		t.Fatalf("viewer masking failed: %d %q", r.StatusCode, body)
	}
	out := filepath.Join(home, "masked.json")
	refused := exec.Command(bin, "export", "--out", out)
	refused.Env = os.Environ()
	if e = refused.Run(); e == nil {
		t.Fatal("plaintext export did not require consent")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("refused export created a file")
	}
	cli(false, "export", "--confirm-plaintext", "--out", out, "--session", "1")
	data, _ := os.ReadFile(out)
	if !json.Valid(data) || bytes.Contains(data, []byte("WindowSecret42")) {
		t.Fatal("export leaked a secret")
	}
	backup := filepath.Join(home, "backup.db")
	cli(false, "backup", "--out", backup)
	cli(false, "verify", "--file", backup)
	t.Log("PROTECTION raw_masked_before_storage=true command_masked=true viewer_masked=true export_opt_in=true live_encrypted_backup_verified=true")

	for _, s := range screens {
		s.exit(t)
	}
	cli(false, "off")
	db := filepath.Join(home, ".pentrail/pentrail.db")
	st, e := store.Open(db, []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	ss, e := st.ListSessions()
	if e != nil || len(ss) != 3 {
		t.Fatal(ss, e)
	}
	var all bytes.Buffer
	totalCommands := 0
	for _, session := range ss {
		raw, missing, e := st.ReadRange(session.ID, 0, session.RawBytes)
		if e != nil || missing != 0 {
			t.Fatal(missing, e)
		}
		all.Write(raw)
		cmds, e := st.ListCommands(session.ID)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("session %s commands=%d", session.Shell, len(cmds))
		totalCommands += len(cmds)
		events, e := st.ListCaptureEvents(session.ID)
		if e != nil || len(events) != 3 {
			t.Fatal(events, e)
		}
	}
	for _, marker := range []string{"WIN_powershell_FIRST", "WIN_pwsh_FIRST", "WIN_CMD_FIRST", "WIN_RESUMED_0", "WIN_RESUMED_1", "WIN_RESUMED_2"} {
		if !bytes.Contains(all.Bytes(), []byte(marker)) {
			t.Fatalf("missing raw marker %s", marker)
		}
	}
	for _, sensitive := range []string{"PRIVATE_", key, "WindowSecret42"} {
		if at := bytes.Index(all.Bytes(), []byte(sensitive)); at >= 0 {
			t.Fatalf("unexpected synthetic value %q at %d: %q", sensitive, at, all.Bytes()[max(0, at-120):min(all.Len(), at+180)])
		}
	}

	if totalCommands < 5 {
		t.Fatalf("command segmentation failed: %d", totalCommands)
	}
	st.Close()
	disk, e := os.ReadFile(db)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(disk, []byte("WIN_powershell_FIRST")) || bytes.HasPrefix(disk, []byte("SQLite format")) {
		t.Fatal("plaintext DB")
	}
	bad, e := store.Open(db, []byte("wrong-key"))
	if e == nil {
		bad.Close()
		t.Fatal("wrong key accepted")
	}
	t.Log("REOPEN sessions=3 encrypted=true wrong_key_rejected=true private_data_absent=true resumed_output_present=true raw_missing=0")
}
