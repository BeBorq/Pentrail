//go:build windows

package localipc

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// spellings returns the long and the 8.3 short spelling of an existing
// directory of this test. Skipped only where the file system has no short
// names; on GitHub Actions (temp directory under C:\Users\RUNNER~1) the alias
// exists and the test must run.
func spellings(t *testing.T) (long, short string) {
	t.Helper()
	dir := t.TempDir()
	long, err := longPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	short, err = shortPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(long, short) {
		// A directory below this one with a long name gets a short alias if the
		// volume creates short names at all.
		sub := filepath.Join(dir, "a-directory-with-a-long-name")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		long, _ = longPath(sub)
		short, _ = shortPath(sub)
	}
	if strings.EqualFold(long, short) {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no 8.3 alias under %s on the CI runner; this case must run there", dir)
		}
		t.Skip("this volume has no 8.3 short names")
	}
	return long, short
}

func echoOnce(t *testing.T, listen, dial string) {
	t.Helper()
	l, err := Listen(listen) // the endpoint file does not exist yet
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	c, err := Dial(dial, 2*time.Second)
	if err != nil {
		t.Fatalf("listen %s, dial %s: %v", listen, dial, err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("listen %s, dial %s: %q %v", listen, dial, b, err)
	}
}

// The same endpoint is reached through its long, short and differently cased
// spellings, in both directions, while the endpoint file does not exist at
// Listen time.
func TestPipeNameSameForAllSpellings(t *testing.T) {
	long, short := spellings(t)
	for i, c := range []struct{ listen, dial string }{
		{short, long}, {long, short}, {short, strings.ToUpper(long)}, {strings.ToLower(short), long}, {long, long},
	} {
		name := filepath.Base(t.Name()) + string(rune('a'+i)) + ".sock"
		echoOnce(t, filepath.Join(c.listen, name), filepath.Join(c.dial, name))
	}
	a, _ := pipeName(filepath.Join(short, "x.sock"))
	b, _ := pipeName(filepath.Join(long, "x.sock"))
	if a != b {
		t.Fatalf("pipe names differ: %s %s", a, b)
	}
}

// A server of an older version named its pipe after the spelling it was given.
// A new client that has another spelling of the same path still reaches it.
func TestDialReachesOldServerOfOtherSpelling(t *testing.T) {
	long, short := spellings(t)
	sid, err := UserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := descriptor()
	for _, c := range []struct{ server, client string }{{short, long}, {long, short}} {
		path := filepath.Join(c.server, "old.sock")
		abs, _ := filepath.Abs(path)
		old := hashName(sid, strings.ToLower(abs)) // the naming before this change
		l, err := winio.ListenPipe(old, &winio.PipeConfig{SecurityDescriptor: sd})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			if c, err := l.Accept(); err == nil {
				c.Write([]byte("old"))
				c.Close()
			}
		}()
		conn, err := Dial(filepath.Join(c.client, "old.sock"), 2*time.Second)
		if err != nil {
			l.Close()
			t.Fatalf("old server on %s not reached from %s: %v", c.server, c.client, err)
		}
		b, _ := io.ReadAll(conn)
		conn.Close()
		l.Close()
		if string(b) != "old" {
			t.Fatalf("read %q", b)
		}
	}
}

// No pipe under any spelling: Dial reports "not found" (stale), and nothing
// else answers for another path.
func TestDialMissingEndpointIsStale(t *testing.T) {
	long, _ := spellings(t)
	other := filepath.Join(long, "other.sock")
	l, err := Listen(filepath.Join(long, "present.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, err = Dial(other, time.Second)
	if err == nil || !IsStaleError(err) || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("dial of a missing endpoint: %v", err)
	}
}

// EndpointOwnerRunning: the listening process (this test) is running and wrote
// the file; a missing file, a PID that does not run, and a process started
// after the file was written are confirmed ends. A file that cannot be read
// (locked) or does not hold a PID is unknown: an error, never "ended".
func TestEndpointOwnerRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "own.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if running, err := EndpointOwnerRunning(path); !running || err != nil {
		t.Fatalf("this process wrote the endpoint and runs: %v %v", running, err)
	}
	ended := func(name, why string) {
		t.Helper()
		if running, err := EndpointOwnerRunning(filepath.Join(dir, name)); running || err != nil {
			t.Fatalf("%s: %v %v", why, running, err)
		}
	}
	os.WriteFile(filepath.Join(dir, "gone.sock"), []byte("4294967290"), 0o600)
	ended("gone.sock", "a PID that does not run")
	old := filepath.Join(dir, "old.sock")
	os.WriteFile(old, []byte(strconv.Itoa(os.Getpid())), 0o600)
	past := time.Now().Add(-24 * time.Hour)
	os.Chtimes(old, past, past) // written long before this process started: PID reuse
	ended("old.sock", "a process started after the endpoint file was written")
	ended("missing.sock", "a missing file")

	unknown := func(p, why string) {
		t.Helper()
		if running, err := EndpointOwnerRunning(p); running || err == nil {
			t.Fatalf("%s: reported as checked (%v, %v)", why, running, err)
		}
	}
	bad := filepath.Join(dir, "bad.sock")
	os.WriteFile(bad, []byte("not a pid"), 0o600)
	unknown(bad, "a file that does not name a process")
	empty := filepath.Join(dir, "empty.sock")
	os.WriteFile(empty, nil, 0o600)
	unknown(empty, "an empty file")
	locked := filepath.Join(dir, "locked.sock")
	os.WriteFile(locked, []byte(strconv.Itoa(os.Getpid())), 0o600)
	unlock := lockMarkerForRead(t, locked) // fails the test if os.ReadFile still succeeds
	unknown(locked, "a locked file of a running writer")
	unlock() // fails the test if the marker is not readable again
	if running, err := EndpointOwnerRunning(locked); !running || err != nil {
		t.Fatalf("after the lock is released: %v %v", running, err)
	}
}

// An older server named its pipe after the short directory and the long file
// name before the endpoint file existed; the file then got its own 8.3 alias.
// Clients spelling the file long or short still reach that server. Skipped
// only where the volume makes no short names (never on GitHub Actions).
func TestDialReachesOldServerWhoseLeafGotShortAlias(t *testing.T) {
	long, short := spellings(t)
	sid, err := UserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := descriptor()
	base := "0123456789abcdef.sock"
	oldName := hashName(sid, strings.ToLower(filepath.Join(short, base))) // old naming, before the file existed
	l, err := winio.ListenPipe(oldName, &winio.PipeConfig{SecurityDescriptor: sd})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.WriteFile(filepath.Join(long, base), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	leafShort, err := shortPath(filepath.Join(long, base))
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(filepath.Base(leafShort), base) {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no 8.3 alias for %s on the CI runner", base)
		}
		t.Skip("the endpoint file got no 8.3 alias on this volume")
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("old"))
			c.Close()
		}
	}()
	for _, client := range []string{filepath.Join(long, base), leafShort, filepath.Join(short, base)} {
		c, err := Dial(client, 2*time.Second)
		if err != nil {
			t.Fatalf("old server not reached from %s: %v", client, err)
		}
		b, _ := io.ReadAll(c)
		c.Close()
		if string(b) != "old" {
			t.Fatalf("%s: read %q", client, b)
		}
	}
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
