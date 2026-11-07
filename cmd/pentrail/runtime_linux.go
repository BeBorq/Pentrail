//go:build linux

package main

import (
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/capture"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/hooks"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/store"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"
)

// cmdStart spawns a detached session server (which owns the PTY, shell and
// store) and then attaches to it as a client. Because the server is detached,
// the shell and the capture survive this client dying, the terminal closing, or
// an explicit detach (Ctrl-\).
func cmdStart(args []string) (retErr error) {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	dbPath = dbidentity.Canonical(dbPath)
	shell, args := flagValue(args, "--shell", os.Getenv("SHELL"))
	auto, _ := flagBool(args, "--auto")
	if shell == "" {
		shell = "/bin/bash"
	}
	attached := false
	defer func() {
		if auto && !attached && retErr != nil {
			fmt.Fprintln(os.Stderr, "pentrail: automatic capture unavailable; starting a normal shell:", retErr)
			if err := syscall.Exec(shell, []string{shell, "-i"}, append(os.Environ(), "PENTRAIL_AUTOSTART_SKIP=1")); err != nil {
				retErr = fmt.Errorf("%v; fallback shell: %w", retErr, err)
			}
		}
	}()
	unlock, lockErr := background.Lock()
	if lockErr != nil {
		return lockErr
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	if auto {
		state, err := userState()
		if err != nil {
			return err
		}
		if !autoEnabled() {
			return fmt.Errorf("automatic capture is disabled or locked")
		}
		dbPath = state.Database
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return err
	}
	runDir := filepath.Join(filepath.Dir(dbPath), "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}

	pass, err := getPassphrase()
	if err != nil {
		return err
	}

	if err = selectDatabaseForStart(dbPath, pass); err != nil {
		zero(pass)
		return err
	}
	sidTok, err := newToken()
	if err != nil {
		zero(pass)
		return err
	}
	sid := sidTok[:16]
	sockPath := filepath.Join(runDir, sid+".sock")
	logPath := filepath.Join(runDir, sid+".log")

	// Hand the passphrase to the server over a pipe (FD 3) — never via env or
	// disk, so neither the environment nor another process sees the key.
	pr, pw, err := os.Pipe()
	if err != nil {
		zero(pass)
		return err
	}
	self, err := os.Executable()
	if err != nil {
		zero(pass)
		return err
	}
	srv := exec.Command(self, "__session-server", "--db", dbPath, "--shell", shell, "--sock", sockPath)
	srv.ExtraFiles = []*os.File{pr} // FD 3 in the child
	srv.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if logf, _ := os.Create(logPath); logf != nil {
		srv.Stdout, srv.Stderr = logf, logf
	}
	if err := srv.Start(); err != nil {
		zero(pass)
		pr.Close()
		pw.Close()
		return err
	}
	pr.Close()
	_, _ = pw.Write(pass)
	zero(pass)
	pw.Close()
	_ = srv.Process.Release() // detached: we do not wait on it

	if err := waitForSocket(sockPath, 30*time.Second); err != nil {
		data, _ := os.ReadFile(logPath)
		return fmt.Errorf("session server did not come up: %w\n--- server log ---\n%s", err, string(data))
	}

	if !auto {
		fmt.Fprint(os.Stderr, "pentrail: attached. Detach with Ctrl-\\ (session keeps running); type 'exit' to stop it.\r\n")
	}
	unlock()
	unlock = nil

	attached = true
	return capture.RunClient(sockPath)
}

// cmdSessionServer is the hidden detached server process.
func cmdSessionServer(args []string) error {
	dbPath, args := flagValue(args, "--db", defaultDBPath())
	dbPath = dbidentity.Canonical(dbPath)
	shell, args := flagValue(args, "--shell", "/bin/bash")
	sockPath, _ := flagValue(args, "--sock", "")
	if sockPath == "" {
		return fmt.Errorf("session server: missing --sock")
	}

	// Passphrase arrives on FD 3.
	var pass []byte
	if kf := os.NewFile(3, "pentrail-key"); kf != nil {
		pass, _ = io.ReadAll(kf)
		kf.Close()
	}
	_ = capture.Mlockall()

	st, err := store.Open(dbPath, pass)
	zero(pass)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	sessionID, err := st.StartSession(filepath.Base(shell), host, version)
	if err != nil {
		st.Close()
		return err
	}

	artDir := filepath.Join(filepath.Dir(dbPath), "artifacts", strconv.FormatInt(sessionID, 10))
	if err := os.MkdirAll(artDir, 0o700); err == nil {
		os.Setenv("PENTRAIL_ARTIFACTS", artDir)
	}
	markerToken, err := newToken()
	if err != nil {
		st.Close()
		return err
	}
	os.Setenv("PENTRAIL_TOKEN", markerToken)
	os.Setenv("PENTRAIL_SOCKET", sockPath)
	if self, err := os.Executable(); err == nil {
		os.Setenv("PENTRAIL_BIN", self)
	}

	shellArgs, cleanup := prepareShell(shell)
	defer cleanup()

	runErr := capture.RunServer(capture.Options{
		Shell: shell, Args: shellArgs, Store: st, DatabaseID: dbidentity.ID(dbPath), SessionID: sessionID,
		ArtifactDir: artDir, MarkerToken: markerToken,
	}, sockPath)

	// RunServer finalizes the store before reporting its result to clients.
	if closeErr := st.Close(); closeErr != nil && runErr == nil {
		return closeErr
	}
	return runErr
}

// cmdAttach attaches to a running session (the newest live one by default).
func cmdAttach(args []string) error {
	sock, args := flagValue(args, "--sock", "")
	dbPath, _ := flagValue(args, "--db", defaultDBPath())
	if sock == "" {
		runDir := filepath.Join(filepath.Dir(dbPath), "run")
		s, err := newestLiveSocket(runDir)
		if err != nil {
			return err
		}
		sock = s
	}
	fmt.Fprintf(os.Stderr, "pentrail: attached to %s. Detach with Ctrl-\\.\r\n", sock)
	return capture.RunClient(sock)
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, err := localipc.Dial(path, time.Second); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

// newestLiveSocket returns the most recently created socket in runDir that still
// accepts a connection (a live session), cleaning up ones that don't.
func newestLiveSocket(runDir string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(runDir, "*.sock"))
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.ModTime().After(fj.ModTime())
	})
	for _, m := range matches {
		if c, err := localipc.Dial(m, time.Second); err == nil {
			c.Close()
			return m, nil
		}
		os.Remove(m) // stale socket from a server that is gone
	}
	return "", fmt.Errorf("no live pentrail session found in %s", runDir)
}

// prepareShell builds the argv that injects our hook, sourcing the user's own
// rc first so their environment is intact. Returns a cleanup for temp files.
func prepareShell(shell string) ([]string, func()) {
	base := filepath.Base(shell)
	hook, ok := hooks.For(base)
	if !ok {
		// Unknown shell: no segmentation, but raw capture still works.
		return []string{"-i"}, func() {}
	}

	switch base {
	case "bash":
		tmp, err := os.CreateTemp("", "pentrail-bashrc-*.sh")
		if err != nil {
			return []string{"-i"}, func() {}
		}
		fmt.Fprintln(tmp, `[ -f "$HOME/.bashrc" ] && source "$HOME/.bashrc"`)
		fmt.Fprintln(tmp, hook)
		tmp.Close()
		return []string{"--rcfile", tmp.Name(), "-i"}, func() { os.Remove(tmp.Name()) }

	case "zsh":
		dir, err := os.MkdirTemp("", "pentrail-zdot-*")
		if err != nil {
			return []string{"-i"}, func() {}
		}
		rc := filepath.Join(dir, ".zshrc")
		originalDir := os.Getenv("ZDOTDIR")
		if originalDir == "" {
			originalDir, _ = os.UserHomeDir()
		}
		originalRC := filepath.Join(originalDir, ".zshrc")
		body := "export ZDOTDIR=" + shellQuote(originalDir) + "\n[ -f " + shellQuote(originalRC) + " ] && source " + shellQuote(originalRC) + "\n" + hook + "\n"
		if err := os.WriteFile(rc, []byte(body), 0o600); err != nil {
			os.RemoveAll(dir)
			return []string{"-i"}, func() {}
		}
		os.Setenv("ZDOTDIR", dir) // capture copies os.Environ() into the child
		return []string{"-i"}, func() { os.RemoveAll(dir) }
	}
	return []string{"-i"}, func() {}
}

func cmdAutoCheck() bool { return false }
