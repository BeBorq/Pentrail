//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/capture"
	"github.com/BeBorq/Pentrail/internal/hooks"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

const commandProcessor = `Software\Microsoft\Command Processor`

func cmdSetup(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pentrail setup powershell|pwsh|cmd [--profile PATH]")
	}
	if strings.EqualFold(args[0], "windows") {
		for _, kind := range []string{"powershell", "pwsh", "cmd"} {
			if kind == "pwsh" {
				if _, e := exec.LookPath("pwsh.exe"); e != nil {
					continue
				}
			}
			if e := cmdSetup(append([]string{kind}, args[1:]...)); e != nil {
				return fmt.Errorf("setup %s: %w", kind, e)
			}
		}
		return nil
	}
	kind := strings.ToLower(args[0])
	if kind != "cmd" && kind != "powershell" && kind != "pwsh" {
		return errors.New("Windows supports powershell, pwsh and cmd")
	}
	unlock, e := background.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := userState()
	if e != nil {
		return e
	}
	db, args := flagValue(args, "--db", s.Database)
	if !sameDatabase(s.Database, db) && s.Enabled {
		return errors.New("disable recording before changing the database")
	}
	if !sameDatabase(s.Database, db) {
		if e = checkNoRecordingSessions(s.Database); e != nil {
			return e
		}
	}
	s.Database, e = filepath.Abs(db)
	if e != nil {
		return e
	}
	allow, args := flagBool(args, "--allow-plain")
	if !store.Encrypted() && !allow {
		return errors.New("use a SQLCipher build; --allow-plain is only for synthetic development data")
	}
	artifacts, _ := flagBool(args, "--allow-plain-artifacts")
	s.AllowArtifacts = artifacts
	s.AllowPlain = allow
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return errors.New("LOCALAPPDATA is not set")
	}
	binDir := filepath.Join(local, "Pentrail", "bin")
	if e = localipc.ProtectDir(binDir); e != nil {
		return e
	}
	bin := filepath.Join(binDir, "pentrail.exe")
	self, e := os.Executable()
	if e != nil {
		return e
	}
	if !strings.EqualFold(self, bin) {
		b, e := os.ReadFile(self)
		if e != nil {
			return e
		}
		if e = os.WriteFile(bin, b, 0700); e != nil {
			return fmt.Errorf("install executable (close running copies before upgrading): %w", e)
		}
	}
	if kind == "cmd" {
		script := cmdStartup(bin)
		scriptPath := filepath.Join(background.Dir(), "cmd-autorun.cmd")
		if e = os.WriteFile(scriptPath, []byte(script), 0600); e != nil {
			return e
		}
		regKey, _ := flagValue(args, "--registry-key", commandProcessor)
		if e = setupCMDRegistry(regKey, scriptPath); e != nil {
			return e
		}
	} else {
		shell, e := resolveShell(kind)
		if e != nil {
			return e
		}
		profile, args := flagValue(args, "--profile", "")
		custom := profile != ""
		_ = args
		if profile == "" {
			profile, e = queryPSProfile(shell)
			if e != nil {
				return e
			}
		}
		if profile == "" {
			return errors.New("could not determine PowerShell profile")
		}
		if e = setupPSProfile(profile, bin, shell, custom); e != nil {
			return e
		}
	}
	if e = background.Save(s); e != nil {
		return e
	}
	fmt.Printf("pentrail: configured %s. Enable with %s on; then open a new terminal.\n", kind, bin)
	return nil
}
func cmdStartup(bin string) string {
	// Keep the batch file ASCII: cmd.exe decodes source using the active OEM
	// code page. Unicode paths expand from environment variables inside CMD.
	return "@echo off\r\nif defined PENTRAIL (\r\n\"%LOCALAPPDATA%\\Pentrail\\bin\\pentrail.exe\" __same-console\r\nif not errorlevel 1 exit /b 0\r\n)\r\nset \"PATH=%LOCALAPPDATA%\\Pentrail\\bin;%PATH%\"\r\nfor %%e in (%errorlevel%) do (\r\nsetlocal\r\nset \"__ptOldError=%%e\"\r\n)\r\n\"%LOCALAPPDATA%\\Pentrail\\bin\\pentrail.exe\" __cmd-check\r\nif errorlevel 1 (endlocal & exit /b %__ptOldError%)\r\nendlocal\r\n\"%LOCALAPPDATA%\\Pentrail\\bin\\pentrail.exe\" start --auto --shell \"%ComSpec%\"\r\nif errorlevel 1 (echo pentrail: capture failed; this shell is not recording. 1>&2 & exit /b)\r\nexit\r\n"
}

func setupCMDRegistry(keyPath, script string) error {
	k, _, e := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	old, typ, e := k.GetStringValue("AutoRun")
	exists := e == nil
	if e != nil && e != registry.ErrNotExist {
		return e
	}
	suffix := `call "` + script + `"`
	if strings.Contains(old, suffix) {
		return nil
	}
	// Preserve original registry type/value for restoration. Never overwrite backup.
	backup := filepath.Join(background.Dir(), "cmd-autorun-backup.json")
	if _, e = os.Stat(backup); os.IsNotExist(e) {
		b, _ := json.MarshalIndent(struct {
			Key, Value string
			Type       uint32
			Existed    bool
		}{keyPath, old, typ, exists}, "", "  ")
		if e = os.WriteFile(backup, b, 0600); e != nil {
			return e
		}
	}
	next := suffix
	if strings.TrimSpace(old) != "" {
		next = old + " & " + suffix
	}
	if typ == registry.EXPAND_SZ {
		return k.SetExpandStringValue("AutoRun", next)
	}
	return k.SetStringValue("AutoRun", next)
}
func psStartup(bin, shell, custom string) string {
	return blockStart + "\n" + hooks.PowerShellAutoStart(bin, shell, custom) + blockEnd + "\n"
}
func setupPSProfile(path, bin, shell string, custom bool) error {
	old, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	text, e := decodeProfile(old)
	if e != nil {
		return e
	}
	if a := strings.Index(text, blockStart); a >= 0 {
		b := strings.Index(text[a:], blockEnd)
		if b < 0 {
			return errors.New("incomplete Pentrail profile block; restore backup")
		}
		text = text[:a] + text[a+b+len(blockEnd):]
	}
	if len(old) > 0 {
		if _, e = writeStartupBackup(path, old); e != nil {
			return e
		}
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	// BOM preserves non-ASCII existing profiles in Windows PowerShell 5.1.
	startupProfile := ""
	if custom {
		startupProfile = path
	}
	return os.WriteFile(path, []byte("\ufeff"+psStartup(bin, shell, startupProfile)+text), 0600)
}
func parentCommandLine() (string, error) {
	var info struct {
		Reserved1 uintptr
		PEB       uintptr
		Reserved2 [2]uintptr
		PID       uintptr
		Parent    uintptr
	}
	var size uint32
	if e := windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessBasicInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &size); e != nil {
		return "", e
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(info.Parent))
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(h)
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	if size == 0 || size > 1<<20 {
		return "", errors.New("invalid parent command line length")
	}
	buf := make([]byte, size)
	if e = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &size); e != nil {
		return "", e
	}
	u := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return u.String(), nil
}
func cmdAutoCheck() bool {
	if os.Getenv("PENTRAIL") != "" || !autoEnabled() || !capture.IsTerminal(os.Stdin.Fd()) || !capture.IsTerminal(os.Stdout.Fd()) {
		return false
	}
	line, e := parentCommandLine()
	if e != nil {
		return false
	}
	args, e := windows.DecomposeCommandLine(line)
	if e != nil || len(args) == 0 || !strings.EqualFold(filepath.Base(args[0]), "cmd.exe") {
		return false
	}
	for _, a := range args[1:] {
		if strings.HasPrefix(strings.ToLower(a), "/c") {
			return false
		}
	}
	return true
}

func decodeProfile(b []byte) (string, error) {
	if len(b) >= 2 && ((b[0] == 0xff && b[1] == 0xfe) || (b[0] == 0xfe && b[1] == 0xff)) {
		if len(b)%2 != 0 {
			return "", errors.New("invalid UTF-16 profile; unchanged")
		}
		var order binary.ByteOrder = binary.LittleEndian
		if b[0] == 0xfe {
			order = binary.BigEndian
		}
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = order.Uint16(b[2+2*i:])
		}
		return string(utf16.Decode(u)), nil
	}
	if !utf8.Valid(b) {
		return "", errors.New("profile must be UTF-8 or UTF-16; original was left unchanged")
	}
	return strings.TrimPrefix(string(b), "\ufeff"), nil
}

func queryPSProfile(shell string) (string, error) {
	c := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $PROFILE.CurrentUserAllHosts")
	backgroundCommand(c)
	b, e := c.Output()
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff")), nil
}
