//go:build windows

package main

import (
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func reviewHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("PENTRAIL_DB", "")
	return home
}
func TestReviewSetupDBSwitchMustNotEscapeOff(t *testing.T) {
	home := reviewHome(t)
	a := filepath.Join(home, "A", "a.db")
	b := filepath.Join(home, "B", "b.db")
	run := filepath.Join(filepath.Dir(a), "run")
	os.MkdirAll(run, 0700)
	path := filepath.Join(run, "0123456789abcdef.sock")
	l, e := localipc.Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	var recording atomic.Bool
	recording.Store(true)
	hub := sessionio.NewHub()
	hub.SetControl(func(op string) (sessionio.ControlState, error) {
		if op == "off" {
			recording.Store(false)
		}
		return sessionio.ControlState{SessionID: 1, Recording: recording.Load(), DatabaseID: dbidentity.ID(a)}, nil
	})
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go hub.ServeConn(c, func(byte, []byte) error { return nil })
		}
	}()
	if e = background.Save(background.State{Enabled: true, Database: a, AllowPlain: true}); e != nil {
		t.Fatal(e)
	}
	e = cmdSetup([]string{"powershell", "--db", b, "--profile", filepath.Join(home, "test-profile.ps1"), "--allow-plain"})
	if e == nil {
		t.Fatal("changing the DB while recording was accepted")
	}
	if e = cmdOff(); e != nil {
		t.Fatal(e)
	}
	state, _ := background.Load()
	t.Logf("after off: enabled=%v configured_db=%s old_session_recording=%v", state.Enabled, state.Database, recording.Load())
	if recording.Load() {
		t.Fatal("off reported success while the original session is still recording")
	}
}
func TestReviewOpenMustNotReuseOtherDatabaseViewer(t *testing.T) {
	home := reviewHome(t)
	l, e := net.Listen("tcp", "127.0.0.1:7878")
	if e != nil {
		t.Skip("test port in use")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"database_id":%q}`, dbidentity.ID(filepath.Join(home, "a.db")))
	})}
	go server.Serve(l)
	defer server.Close()
	os.MkdirAll(filepath.Join(background.Dir(), "run"), 0700)
	os.WriteFile(filepath.Join(background.Dir(), "run/viewer.log"), []byte("http://127.0.0.1:7878/?t=abcd"), 0600)
	b := filepath.Join(home, "B", "missing-b.db")
	background.Save(background.State{Database: b})
	if viewerReady("http://127.0.0.1:7878/?t=abcd", dbidentity.ID(b)) {
		t.Fatal("old database A viewer was accepted for database B")
	}

}
func TestReviewDeadEndpointMustNotBreakEveryOff(t *testing.T) {
	home := reviewHome(t)
	db := filepath.Join(home, "a.db")
	run := filepath.Join(home, "run")
	os.MkdirAll(run, 0700)
	os.WriteFile(filepath.Join(run, "0123456789abcdef.sock"), []byte("99999999"), 0600)
	background.Save(background.State{Database: db})
	if e := cmdOff(); e != nil {
		t.Fatalf("no sessions exist, but stale endpoint makes off fail: %v", e)
	}
}
