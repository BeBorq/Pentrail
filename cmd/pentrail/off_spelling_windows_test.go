//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"golang.org/x/sys/windows"
)

func spellingOf(t *testing.T, p string, f func(*uint16, *uint16, uint32) (uint32, error)) string {
	t.Helper()
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := f(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		t.Fatalf("path conversion of %s: %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// serveRecording listens at path (as a session server would) and answers
// control requests for a session of database db that records until "off".
func serveRecording(t *testing.T, path, db string) *atomic.Bool {
	t.Helper()
	l, err := localipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var recording atomic.Bool
	recording.Store(true)
	hub := sessionio.NewHub()
	hub.SetControl(func(op string) (sessionio.ControlState, error) {
		switch op {
		case "off":
			recording.Store(false)
		case "on":
			recording.Store(true)
		}
		return sessionio.ControlState{SessionID: 1, Recording: recording.Load(), DatabaseID: dbidentity.ID(db)}, nil
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go hub.ServeConn(c, func(byte, []byte) error { return nil })
		}
	}()
	return &recording
}

// A session server that listened on the 8.3 short spelling of its run
// directory is paused by `off`, whose configured database has the long
// spelling (dbidentity.Canonical expands it), and `on` resumes it.
func TestOffPausesSessionListeningOnShortSpelling(t *testing.T) {
	home := reviewHome(t)
	longHome := spellingOf(t, home, windows.GetLongPathName)
	db := filepath.Join(longHome, "a-database-directory", "a.db")
	run := filepath.Join(filepath.Dir(db), "run")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	shortRun := spellingOf(t, run, windows.GetShortPathName)
	if strings.EqualFold(shortRun, run) {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no 8.3 alias for %s on the CI runner; this case must run there", run)
		}
		t.Skip("this volume has no 8.3 short names")
	}
	recording := serveRecording(t, filepath.Join(shortRun, "0123456789abcdef.sock"), db)
	if err := background.Save(background.State{Enabled: true, Database: db, AllowPlain: true}); err != nil {
		t.Fatal(err)
	}
	if err := cmdOff(); err != nil {
		t.Fatal(err)
	}
	if recording.Load() {
		t.Fatal("off reported success while the session listening on the short spelling still records")
	}
	if err := controlAll(dbidentity.Canonical(db), "on"); err != nil {
		t.Fatal(err)
	}
	if !recording.Load() {
		t.Fatal("on did not reach the session")
	}
}

// An endpoint file whose writer is still running but whose pipe cannot be
// reached is a live session that was not paused: `off` must report it, not
// succeed. (Here the writer is this test process itself, which listens on no
// pipe for that file.)
func TestOffReportsLiveSessionItCannotReach(t *testing.T) {
	home := reviewHome(t)
	db := filepath.Join(home, "A", "a.db")
	run := filepath.Join(filepath.Dir(db), "run")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(run, "fedcba9876543210.sock")
	if err := os.WriteFile(sock, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := background.Save(background.State{Enabled: true, Database: db, AllowPlain: true}); err != nil {
		t.Fatal(err)
	}
	err := cmdOff()
	if err == nil {
		t.Fatal("off reported success although a running session could not be reached")
	}
	if s, _ := background.Load(); s.Enabled {
		t.Fatal("off did not disable recording for new terminals")
	}
	t.Logf("off: %v", err)
	// The same file from a process that has ended is a stale endpoint: skipped.
	os.WriteFile(sock, []byte("4294967290"), 0o600)
	background.Save(background.State{Enabled: true, Database: db, AllowPlain: true})
	if err := cmdOff(); err != nil {
		t.Fatalf("a stale endpoint was reported as a live session: %v", err)
	}
}
