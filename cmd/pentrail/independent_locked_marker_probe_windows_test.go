//go:build windows

package main

import (
	"errors"
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
	unlock := lockMarkerForRead(t, sock) // fails the test if os.ReadFile still succeeds ("probe did not make marker unreadable")
	if err := cmdOff(); err == nil {
		t.Fatal("off reported success although the live endpoint writer could not be checked")
	}
	if s, _ := background.Load(); s.Enabled {
		t.Fatal("off did not disable recording for new terminals")
	}
	unlock() // fails the test if the marker is not readable again
}

// lockMarkerForRead makes path unreadable through any other handle, also in
// this process: a separately opened, share-compatible handle takes an
// exclusive byte-range lock (LockFileEx with LOCKFILE_EXCLUSIVE_LOCK |
// LOCKFILE_FAIL_IMMEDIATELY) over the whole marker and well beyond its end.
// ReadFile through another handle then fails with ERROR_LOCK_VIOLATION
// (https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).
// A share mode of 0 alone is not enough: on the hosted Windows runner the
// marker was still readable. The test checks that os.ReadFile really fails
// while locked; the returned function unlocks and closes the handle and checks
// that the marker is readable again.
func lockMarkerForRead(t *testing.T, path string) (unlock func()) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0) // synchronous handle
	if err != nil {
		t.Fatal(err)
	}
	const span = 1 << 20          // nonempty, from offset 0, covers the whole marker
	ol := new(windows.Overlapped) // Offset 0; required by LockFileEx also for synchronous handles
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, span, 0, ol); err != nil {
		windows.CloseHandle(h)
		t.Fatalf("lock %s: %v", path, err)
	}
	done := false
	release := func() {
		if done {
			return
		}
		done = true
		uerr := windows.UnlockFileEx(h, 0, span, 0, new(windows.Overlapped))
		cerr := windows.CloseHandle(h)
		if uerr != nil || cerr != nil {
			t.Errorf("unlock %s: %v %v", path, uerr, cerr)
		}
	}
	t.Cleanup(release)
	if _, err := os.ReadFile(path); err == nil {
		release()
		t.Fatalf("probe did not make marker unreadable: %s is still readable while locked", path)
	} else if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Logf("read while locked: %v", err)
	}
	return func() {
		release()
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("%s is not readable after unlock: %v", path, err)
		}
	}
}
