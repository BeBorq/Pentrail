//go:build windows

package main

import (
	"github.com/BeBorq/Pentrail/internal/background"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Independent synthetic probe: the same live writer as the existing
// unreachable-session regression, but its endpoint marker is temporarily
// unreadable. No application logic is changed by this probe.
func TestIndependentOffMustNotClaimSuccessWithUnreadableLiveMarker(t *testing.T) {
	home := reviewHome(t)
	db := filepath.Join(home, "A", "a.db")
	run := filepath.Join(filepath.Dir(db), "run")
	if err := os.MkdirAll(run, 0700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(run, "fedcba9876543210.sock")
	if err := os.WriteFile(sock, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := background.Save(background.State{Enabled: true, Database: db, AllowPlain: true}); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(sock)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if _, err := os.ReadFile(sock); err == nil {
		t.Fatal("probe did not make marker unreadable")
	}
	if err := cmdOff(); err == nil {
		t.Fatal("off reported success although the live endpoint writer could not be checked")
	}
}
