//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/capture"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/hooks"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func encodedPS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func resolveShell(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", "powershell":
		s = "powershell.exe"
	case "pwsh":
		s = "pwsh.exe"
	case "cmd":
		s = "cmd.exe"
	}
	return exec.LookPath(s)
}
func backgroundCommand(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP}
}
func spawnWithKey(kind string, args []string, key []byte, logPath string) error {
	if e := localipc.ProtectDir(filepath.Dir(logPath)); e != nil {
		return e
	}
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	self, e := os.Executable()
	if e != nil {
		return e
	}
	c := exec.Command(self, append([]string{kind}, args...)...)
	c.Stdin = strings.NewReader(string(key))
	c.Stdout = f
	c.Stderr = f
	backgroundCommand(c)
	if e = c.Start(); e != nil {
		return e
	}
	pidPath := strings.TrimSuffix(logPath, filepath.Ext(logPath)) + ".pid"
	if e = os.WriteFile(pidPath, []byte(strconv.Itoa(c.Process.Pid)), 0600); e != nil {
		c.Process.Kill()
		return e
	}
	return c.Process.Release()
}
func removeAgentEndpoint() error {
	e := os.Remove(background.AgentSocket())
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func openBrowser(link string) error {
	u, e := windows.UTF16PtrFromString(link)
	if e != nil {
		return e
	}
	verb, _ := windows.UTF16PtrFromString("open")
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}
func cmdStart(args []string) (retErr error) {
	db, args := flagValue(args, "--db", defaultDBPath())
	db = dbidentity.Canonical(db)
	shell, args := flagValue(args, "--shell", "powershell")
	auto, _ := flagBool(args, "--auto")
	shell, e := resolveShell(shell)
	if e != nil {
		return e
	}
	unlock, e := background.Lock()
	if e != nil {
		return e
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	if auto {
		s, e := userState()
		if e != nil {
			return e
		}
		if !autoEnabled() {
			return errors.New("automatic capture disabled or key locked")
		}
		db = s.Database
	}
	if e = ensureDatabaseDir(filepath.Dir(db)); e != nil {
		return e
	}
	run := filepath.Join(filepath.Dir(db), "run")
	if e = localipc.ProtectDir(run); e != nil {
		return e
	}
	key, e := getPassphrase()
	if e != nil {
		return e
	}
	defer zero(key)
	if e = selectDatabaseForStart(db, key); e != nil {
		return e
	}
	token, e := newToken()
	if e != nil {
		return e
	}
	sock := filepath.Join(run, token[:16]+".sock")
	profile, _ := flagValue(args, "--startup-profile", "")
	serverArgs := []string{"--db", db, "--shell", shell, "--sock", sock}
	if profile != "" {
		serverArgs = append(serverArgs, "--startup-profile", profile)
	}
	if auto && strings.EqualFold(filepath.Base(shell), "cmd.exe") {
		if line, e := parentCommandLine(); e == nil {
			if initial := cmdInitialCommand(line); initial != "" {
				serverArgs = append(serverArgs, "--initial-command", initial)
			}
		}
	}
	if e = spawnWithKey("__session-server", serverArgs, key, filepath.Join(run, token[:16]+".log")); e != nil {
		return e
	}
	if e = waitForSocket(sock, 30*time.Second); e != nil {
		return e
	}
	unlock()
	unlock = nil
	if !auto {
		fmt.Fprintln(os.Stderr, "pentrail: attached; Ctrl-\\ detaches, exit ends this shell.")
	}
	return capture.RunClient(sock)
}
func cmdSessionServer(args []string) error {
	db, args := flagValue(args, "--db", defaultDBPath())
	db = dbidentity.Canonical(db)
	shell, args := flagValue(args, "--shell", "powershell.exe")
	sock, _ := flagValue(args, "--sock", "")
	if sock == "" {
		return errors.New("missing endpoint")
	}
	key, e := background.ReadKeyPipe()
	if e != nil {
		return e
	}
	st, e := store.Open(db, key)
	zero(key)
	if e != nil {
		return e
	}
	defer st.Close()
	host, _ := os.Hostname()
	id, e := st.StartSession(filepath.Base(shell), host, version)
	if e != nil {
		return e
	}
	token, e := newToken()
	if e != nil {
		return e
	}
	art := filepath.Join(filepath.Dir(db), "artifacts", strconv.FormatInt(id, 10))
	if e = localipc.ProtectDir(art); e != nil {
		return e
	}
	os.Setenv("PENTRAIL_TOKEN", token)
	os.Setenv("PENTRAIL_SOCKET", sock)
	os.Setenv("PENTRAIL_ARTIFACTS", art)
	self, _ := os.Executable()
	os.Setenv("PENTRAIL_BIN", self)
	profile, _ := flagValue(args, "--startup-profile", "")
	initial, _ := flagValue(args, "--initial-command", "")
	shellArgs, cleanup, e := prepareWindowsShell(shell, profile, initial)
	if e != nil {
		return e
	}
	defer cleanup()
	return capture.RunServer(capture.Options{Shell: shell, Args: shellArgs, Store: st, DatabaseID: dbidentity.ID(db), SessionID: id, ArtifactDir: art, MarkerToken: token}, sock)
}
func prepareWindowsShell(shell, profile, initial string) ([]string, func(), error) {
	if strings.EqualFold(filepath.Base(shell), "cmd.exe") {
		// Child /D suppresses AutoRun recursion. Existing user AutoRun has already
		// executed in its parent and its environment is inherited.
		// the marker carries the prompt's visible text (0.6.4, see capture.CMDPrompt)
		os.Setenv("PROMPT", capture.CMDPrompt(os.Getenv("PENTRAIL_TOKEN"), os.Getenv("PROMPT")))
		if initial != "" {
			return []string{"/D", "/Q", "/K", "chcp 65001>nul & " + initial}, func() {}, nil
		}
		return []string{"/D", "/Q", "/K", "chcp 65001>nul"}, func() {}, nil
	}
	// Existing profiles run normally; the startup block checks PENTRAIL to avoid
	// a second recorder. The encoded command contains code, never the DB key.
	code := hooks.PowerShell
	args := []string{"-NoLogo", "-NoExit"}
	if profile != "" {
		args = append(args, "-NoProfile")
		code = ". " + psQuote(profile) + "\n" + code
	}
	return append(args, "-EncodedCommand", encodedPS(code)), func() {}, nil
}
func waitForSocket(path string, timeout time.Duration) error {
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		if _, e := sessionio.RequestControl(path, "status"); e == nil {
			return nil
		}
		time.Sleep(30 * time.Millisecond)
	}
	b, _ := os.ReadFile(strings.TrimSuffix(path, ".sock") + ".log")
	return fmt.Errorf("session startup timed out: %s", b)
}
func cmdAttach(args []string) error {
	sock, args := flagValue(args, "--sock", "")
	db, _ := flagValue(args, "--db", defaultDBPath())
	if sock == "" {
		paths := sessionSockets(db)
		for i := len(paths) - 1; i >= 0; i-- {
			if _, e := sessionio.RequestControl(paths[i], "status"); e == nil {
				sock = paths[i]
				break
			}
		}
	}
	if sock == "" {
		return errors.New("no live session")
	}
	return capture.RunClient(sock)
}

// Do not replace ACLs on an existing user-selected parent (e.g. Documents).
func ensureDatabaseDir(path string) error {
	_, e := os.Stat(path)
	if os.IsNotExist(e) {
		return localipc.ProtectDir(path)
	}
	return e
}

func cmdInitialCommand(line string) string {
	m := regexp.MustCompile(`(?i)(?:^|\s)/k\s*(.*)$`).FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}
