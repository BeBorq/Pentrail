//go:build linux

package main

import (
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/store"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func spawnWithKey(kind string, args []string, key []byte, logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()
	defer pw.Close()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(self, append([]string{kind}, args...)...)
	c.ExtraFiles = []*os.File{pr}
	c.Stdout = f
	c.Stderr = f
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = c.Start(); err != nil {
		return err
	}
	pr.Close()
	_, err = pw.Write(key)
	pw.Close()
	_ = c.Process.Release()
	return err
}
func cmdSetup(args []string) error {
	unlock, lockErr := background.Lock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	if len(args) == 0 || (args[0] != "bash" && args[0] != "zsh") {
		return errors.New("usage: pentrail setup bash|zsh [--db PATH] [--allow-plain]")
	}
	shell := args[0]
	s, err := userState()
	if err != nil {
		return err
	}
	next, args := flagValue(args[1:], "--db", s.Database)
	if !sameDatabase(s.Database, next) && s.Enabled {
		return errors.New("disable recording before changing the database")
	}
	if !sameDatabase(s.Database, next) {
		if e := checkNoRecordingSessions(s.Database); e != nil {
			return e
		}
	}
	s.Database = next
	allow, _ := flagBool(args, "--allow-plain")
	if !store.Encrypted() && !allow {
		return errors.New("setup requires SQLCipher; use --allow-plain only for synthetic development data")
	}
	artifacts, _ := flagBool(args, "--allow-plain-artifacts")
	s.AllowArtifacts = artifacts
	s.AllowPlain = allow
	s.Database, err = filepath.Abs(s.Database)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	bin := filepath.Join(home, ".local", "bin", "pentrail")
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(bin), 0700); err != nil {
		return err
	}
	if filepath.Clean(self) != filepath.Clean(bin) {
		b, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(bin), "pentrail-*")
		if err != nil {
			return err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(b); err != nil {
			f.Close()
			return err
		}
		if err = f.Chmod(0700); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if err = os.Rename(name, bin); err != nil {
			return err
		}
	}
	rc := filepath.Join(home, "."+shell+"rc")
	if shell == "zsh" && os.Getenv("ZDOTDIR") != "" {
		rc = filepath.Join(os.Getenv("ZDOTDIR"), ".zshrc")
	}
	old, err := os.ReadFile(rc)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	text := string(old)
	if start := strings.Index(text, blockStart); start >= 0 {
		end := strings.Index(text[start:], blockEnd)
		if end < 0 {
			return errors.New("incomplete Pentrail block in shell rc; restore its backup first")
		}
		text = text[:start] + text[start+end+len(blockEnd):]
	}
	path, _ := exec.LookPath(shell)
	if path == "" {
		path = "/bin/" + shell
	}
	block := fmt.Sprintf("\n%s\nexport PATH=\"$HOME/.local/bin:$PATH\"\nif [ -z \"$PENTRAIL_AUTOSTART_SKIP\" ] && [ -t 0 ] && [ -t 1 ]; then\n  case $- in *i*) if %s __auto-check >/dev/null 2>&1; then exec %s start --auto --shell %s; fi;; esac\nfi\nunset PENTRAIL_AUTOSTART_SKIP\n%s\n", blockStart, shellQuote(bin), shellQuote(bin), shellQuote(path), blockEnd)
	if len(old) > 0 {
		if _, err = writeStartupBackup(rc, old); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(filepath.Dir(rc), 0700); err != nil {
		return err
	}
	// Run before user startup commands, so they execute once in the wrapped
	// shell rather than once in the parent and again in the child.
	if err = os.WriteFile(rc, []byte(block+text), 0600); err != nil {
		return err
	}
	if err = background.Save(s); err != nil {
		return err
	}
	fmt.Printf("pentrail: configured %s; enable with %s on. New terminal windows will record while enabled.\n", rc, bin)
	return nil
}

func removeAgentEndpoint() error {
	e := os.Remove(background.AgentSocket())
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func openBrowser(link string) error {
	c := exec.Command("xdg-open", link)
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	if e := c.Start(); e != nil {
		return fmt.Errorf("open this URL in a browser: %s (%w)", link, e)
	}
	return c.Process.Release()
}

func ensureDatabaseDir(path string) error { return os.MkdirAll(path, 0700) }
