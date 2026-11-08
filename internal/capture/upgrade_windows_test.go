//go:build windows

package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"golang.org/x/sys/windows"
)

// Codex 04V: updating Pentrail while a session of the previous version is
// running. Two DIFFERENT CLI files in separate paths (old, new); a synthetic
// HOME and database. A session started with the old file keeps working —
// its own server process, still the old image, answers a real round trip —
// after a session was started with the new file and the new file read the
// status. Neither executable is replaced. After both sessions end normally,
// the encrypted database, reopened, holds both sessions with their exact
// commands and outputs, no missing bytes and no lost metadata, each session
// marked with the version of the file that recorded it.
//
// Opt-in (native Windows, SQLCipher CLIs, synthetic data only):
//
//	PENTRAIL_OLD_TEST_BINARY=<old pentrail.exe> PENTRAIL_TEST_BINARY=<new pentrail.exe>
//	go test -tags sqlcipher -count=1 -v -run TestUpgradeWhileOldSessionRuns ./internal/capture
//
// It does NOT prove: hand-over of the key agent between versions (the
// sessions get the key from the environment, not from `on`); `setup`/profile
// autostart of a new version; a database schema migration (none between the
// versions it is meant for); other shells (CMD only); Linux.
func TestUpgradeWhileOldSessionRuns(t *testing.T) {
	oldBin, newBin := os.Getenv("PENTRAIL_OLD_TEST_BINARY"), os.Getenv("PENTRAIL_TEST_BINARY")
	if oldBin == "" || newBin == "" {
		t.Skip("opt-in: set PENTRAIL_OLD_TEST_BINARY (previous version) and PENTRAIL_TEST_BINARY (new version) to two different SQLCipher CLI files")
	}
	oldBin, newBin = absClean(t, oldBin), absClean(t, newBin)
	oldSum, newSum := fileSHA(t, oldBin), fileSHA(t, newBin)
	if strings.EqualFold(oldBin, newBin) || oldSum == newSum {
		t.Fatalf("old and new CLI must be two different files in different paths (old %s %s, new %s %s): identical files would make this test pass without testing an update", oldBin, oldSum[:12], newBin, newSum[:12])
	}
	t.Logf("UPGRADE old %s sha256 %s; new %s sha256 %s", oldBin, oldSum, newBin, newSum)
	// Run only private copies in this test's own directories: a process is
	// this test's only if its image is one of these copies (Codex 04W; a
	// shared source path would not prove that).
	oldBin, newBin = privateCopy(t, oldBin, oldSum, "old"), privateCopy(t, newBin, newSum, "new")
	own := []string{oldBin, newBin}

	home := t.TempDir()
	const key = "synthetic-upgrade-key"
	for k, v := range map[string]string{"USERPROFILE": home, "HOME": home, "LOCALAPPDATA": filepath.Join(home, "Local"), "APPDATA": filepath.Join(home, "Roaming"),
		"PENTRAIL": "", "PENTRAIL_SOCKET": "", "PENTRAIL_SESSION": "", "PENTRAIL_DB": "", "PENTRAIL_PASSPHRASE": key} {
		t.Setenv(k, v)
	}
	run := filepath.Join(home, ".pentrail", "run")
	servers := map[string]windows.Handle{} // socket -> handle of THIS test's session server
	t.Cleanup(func() { cleanupOwnServers(home, own, servers) })

	// 1. old session, old file
	oldScreen := openScreen(t, oldBin, []string{"start", "--shell", "cmd"})
	oldScreen.wait(t, ";A\a")
	oldSock := newSocket(t, run, nil)
	oldPID := serverPID(t, oldSock, oldBin, own, servers)
	oldScreen.send(t, "echo OLD^_ONE")
	oldScreen.wait(t, "OLD_ONE")

	// 2. new session, new file, while the old one runs
	newScreen := openScreen(t, newBin, []string{"start", "--shell", "cmd"})
	newScreen.wait(t, ";A\a")
	newSock := newSocket(t, run, []string{oldSock})
	newPID := serverPID(t, newSock, newBin, own, servers)
	if newPID == oldPID {
		t.Fatalf("both sessions report server PID %d", newPID)
	}
	newScreen.send(t, "echo NEW^_ONE")
	newScreen.wait(t, "NEW_ONE")

	// 3. the new file reads the status of both sessions
	status := runCLI(t, newBin, "status")
	t.Logf("UPGRADE status (new CLI):\n%s", status)
	if err := checkStatusSessions(status, []string{oldSock, newSock}); err != nil {
		t.Fatalf("new CLI status does not show exactly both sessions recording: %v\n%s", err, status)
	}
	if st, err := sessionio.RequestControl(oldSock, "status"); err != nil || !st.Recording || st.RootPID <= 0 {
		t.Fatalf("old session control after the new session started: %+v %v", st, err)
	}

	// 4. the old session is still the old process and still works
	if r, _ := windows.WaitForSingleObject(servers[oldSock], 0); r != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("old session server (pid %d) is no longer running", oldPID)
	}
	if img := imageOf(t, servers[oldSock]); !strings.EqualFold(img, oldBin) {
		t.Fatalf("old session server image is %s, want %s", img, oldBin)
	}
	oldScreen.send(t, "echo OLD^_TWO")
	oldScreen.wait(t, "OLD_TWO")
	newScreen.send(t, "echo NEW^_TWO")
	newScreen.wait(t, "NEW_TWO")

	// 5. both end normally; their servers exit
	oldScreen.exit(t)
	newScreen.exit(t)
	for sock, h := range servers {
		if r, _ := windows.WaitForSingleObject(h, 30000); r != windows.WAIT_OBJECT_0 {
			t.Fatalf("session server of %s did not exit within 30 s", filepath.Base(sock))
		}
	}
	if fileSHA(t, oldBin) != oldSum || fileSHA(t, newBin) != newSum {
		t.Fatal("a CLI file changed during the test")
	}

	// 6. reopen the encrypted database
	st, err := store.Open(filepath.Join(home, ".pentrail", "pentrail.db"), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sessions, err := st.ListSessions()
	if err != nil || len(sessions) != 2 {
		t.Fatalf("sessions %+v %v", sessions, err)
	}
	// the session started first is the old one (ids are assigned in order)
	oldS, newS := sessions[0], sessions[1]
	if oldS.ID > newS.ID {
		oldS, newS = newS, oldS
	}
	if oldS.Version == newS.Version || !binaryHas(t, oldBin, oldS.Version) || !binaryHas(t, newBin, newS.Version) {
		t.Fatalf("session versions %q (old) and %q (new) do not identify the two files", oldS.Version, newS.Version)
	}
	checkUpgradeSession(t, st, oldS, "OLD", "NEW")
	checkUpgradeSession(t, st, newS, "NEW", "OLD")
	t.Logf("UPGRADE_PASS old session %d (%s, server pid %d) kept running and answering after new session %d (%s, server pid %d) started and the new CLI read the status; reopened database: both sessions complete, missing 0",
		oldS.ID, oldS.Version, oldPID, newS.ID, newS.Version, newPID)
}

// checkUpgradeSession: both synthetic commands of the session were recorded
// with their outputs in range; no missing bytes; nothing of the other session.
func checkUpgradeSession(t *testing.T, st *store.Store, s store.SessionInfo, own, other string) {
	t.Helper()
	raw, missing, err := st.ReadRange(s.ID, 0, s.RawBytes)
	if err != nil || missing != 0 {
		t.Fatalf("session %d raw: missing %d err %v", s.ID, missing, err)
	}
	if strings.Contains(string(raw), other+"_") {
		t.Fatalf("session %d holds output of the other session", s.ID)
	}
	cmds, err := st.ListCommands(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"ONE", "TWO"} {
		want, out := "echo "+own+"^_"+tok, own+"_"+tok
		found := false
		for _, c := range cmds {
			if c.Command != want {
				continue
			}
			found = true
			b, miss, err := st.ReadRange(s.ID, c.OutStartOff, c.OutEndOff)
			if err != nil || miss != 0 || !strings.Contains(flat50(string(b)), out) {
				t.Fatalf("session %d: output %s not in the range of %q (%d..%d, missing %d, err %v)", s.ID, out, want, c.OutStartOff, c.OutEndOff, miss, err)
			}
		}
		if !found {
			t.Fatalf("session %d: command %q not recorded; commands %+v", s.ID, want, cmds)
		}
	}
}

func absClean(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(a); err != nil || fi.IsDir() {
		t.Fatalf("CLI file %s: %v", a, err)
	}
	return filepath.Clean(a)
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+)?$`)

func binaryHas(t *testing.T, bin, version string) bool {
	t.Helper()
	if !versionRe.MatchString(version) {
		return false
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), version)
}

func runCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Env = os.Environ()
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = c.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		<-done
		t.Fatalf("%s %v: no result within 60 s", filepath.Base(bin), args)
	}
	if err != nil {
		t.Fatalf("%s %v: %v %s", filepath.Base(bin), args, err, out)
	}
	return string(out)
}

// newSocket waits for a session endpoint in run that is not in known.
func newSocket(t *testing.T, run string, known []string) string {
	t.Helper()
	pattern := regexp.MustCompile(`^[0-9a-f]{16}\.sock$`)
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		paths, _ := filepath.Glob(filepath.Join(run, "*.sock"))
		for _, p := range paths {
			if !pattern.MatchString(filepath.Base(p)) {
				continue
			}
			seen := false
			for _, k := range known {
				seen = seen || k == p
			}
			if !seen {
				return p
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no new session endpoint in %s", run)
	return ""
}

// serverPID: the PID written by the session server into its endpoint file.
// The process is opened at once (no PID reuse later) and admitted for
// cleanup only after its image was confirmed to be bin, one of this test's
// private copies; a mismatching process is never registered and its handle
// is closed without terminating it.
func serverPID(t *testing.T, sock, bin string, own []string, servers map[string]windows.Handle) int {
	t.Helper()
	b, err := os.ReadFile(sock)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("endpoint %s: %q", sock, b)
	}
	if err := admitOwn(pid, bin, own, sock, servers); err != nil {
		t.Fatal(err)
	}
	return pid
}

// admitOwn opens pid and registers it under key only if its image is want
// and want is one of own (this test's private copies). Otherwise the handle
// is closed and nothing is registered.
func admitOwn(pid int, want string, own []string, key string, servers map[string]windows.Handle) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("process %d: %v", pid, err)
	}
	img, err := processImage(h)
	if err != nil || !strings.EqualFold(img, want) || !isOwnImage(img, own) {
		windows.CloseHandle(h) // not ours: never terminated
		return fmt.Errorf("process %d runs %q (%v), want this test's copy %s", pid, img, err, want)
	}
	servers[key] = h
	return nil
}

func isOwnImage(img string, own []string) bool {
	for _, o := range own {
		if strings.EqualFold(img, o) {
			return true
		}
	}
	return false
}

// processImage returns the full path of the process's image file in long
// form. QueryFullProcessImageName reports the spelling the process was started
// with, which can contain 8.3 components ("RUNNER~1"); the copies in own are
// long paths. Converting the reported path with GetLongPathName names the same
// file in the same form, so the exact (case-insensitive) comparison with own
// still accepts only that file: a different file never gets the same long
// path. If the conversion fails, the reported path is returned unchanged and
// can only match an identical spelling.
func processImage(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	img := windows.UTF16ToString(buf[:n])
	long := make([]uint16, 32768)
	if m, err := windows.GetLongPathName(&buf[0], &long[0], uint32(len(long))); err == nil && m > 0 && int(m) < len(long) {
		img = windows.UTF16ToString(long[:m])
	}
	return img, nil
}

// privateCopy copies src into a new private directory of this test and
// checks the copy's SHA-256; returns the copy's full long path (the form
// Windows reports as a process image).
func privateCopy(t *testing.T, src, sum, label string) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), label+"-")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, filepath.Base(src))
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := fileSHA(t, dst); got != sum {
		t.Fatalf("copy of %s: sha256 %s, source %s", src, got, sum)
	}
	return longPath(t, dst)
}

func longPath(t *testing.T, p string) string {
	t.Helper()
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		t.Fatalf("long path of %s: %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}

func imageOf(t *testing.T, h windows.Handle) string {
	t.Helper()
	img, err := processImage(h)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// cleanupOwnServers ends only this test's processes: registered handles
// (admitted by admitOwn) whose image is still one of own, and processes named
// in this test's own HOME run files whose image is one of own (this test's
// private copies). Anything else is left running.
func cleanupOwnServers(home string, own []string, servers map[string]windows.Handle) {
	for _, h := range servers {
		if r, _ := windows.WaitForSingleObject(h, 0); r == uint32(windows.WAIT_TIMEOUT) {
			if img, err := processImage(h); err == nil && isOwnImage(img, own) {
				windows.TerminateProcess(h, 1)
				windows.WaitForSingleObject(h, 10000)
			}
		}
		windows.CloseHandle(h)
	}
	files, _ := filepath.Glob(filepath.Join(home, ".pentrail", "run", "*"))
	for _, p := range files {
		if ext := filepath.Ext(p); ext != ".pid" && ext != ".sock" {
			continue
		}
		b, _ := os.ReadFile(p)
		id, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(id))
		if err != nil {
			continue
		}
		if img, err := processImage(h); err == nil && isOwnImage(img, own) {
			windows.TerminateProcess(h, 1)
			windows.WaitForSingleObject(h, 10000)
		}
		windows.CloseHandle(h)
	}
}

// Codex 04W, synthetic negative control (always runs on Windows; no Pentrail
// binary, no session): a process of this test whose image is NOT an admitted
// copy is never registered and survives cleanup; the same process admitted
// with its real image is registered and ended by cleanup.
func TestUpgradeCleanupNeverEndsForeignImage(t *testing.T) {
	if os.Getenv("PENTRAIL_UPGRADE_SLEEPER") == "1" {
		time.Sleep(60 * time.Second)
		return
	}
	self := longPath(t, os.Args[0])
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpgradeCleanupNeverEndsForeignImage$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PENTRAIL_UPGRADE_SLEEPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-exited }) // this test's own child only
	alive := func() bool {
		select {
		case <-exited:
			return false
		default:
			return true
		}
	}
	home := t.TempDir()
	foreign := filepath.Join(t.TempDir(), "not-this-process.exe")
	servers := map[string]windows.Handle{}
	if err := admitOwn(cmd.Process.Pid, foreign, []string{foreign}, "x", servers); err == nil || len(servers) != 0 {
		t.Fatalf("a process with another image was admitted: %v %v", err, servers)
	}
	cleanupOwnServers(home, []string{foreign}, servers)
	time.Sleep(200 * time.Millisecond)
	if !alive() {
		t.Fatal("cleanup ended a process it had not admitted")
	}
	// The same bytes under the same file name in another directory are another
	// file: never admitted (the check is the image path, not its name or
	// content).
	twin := filepath.Join(t.TempDir(), filepath.Base(self))
	if b, err := os.ReadFile(self); err != nil || os.WriteFile(twin, b, 0o700) != nil {
		t.Fatal("copy of the test binary")
	}
	if err := admitOwn(cmd.Process.Pid, longPath(t, twin), []string{longPath(t, twin)}, "x", servers); err == nil || len(servers) != 0 {
		t.Fatalf("a process was admitted for a copy of its image: %v %v", err, servers)
	}
	if err := admitOwn(cmd.Process.Pid, self, []string{self}, "x", servers); err != nil || len(servers) != 1 {
		t.Fatalf("own process not admitted: %v", err)
	}
	cleanupOwnServers(home, []string{self}, servers)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup did not end the admitted process")
	}
}

// A process started through the 8.3 short spelling of its image reports that
// spelling; it is still this test's own image and is admitted, while a
// foreign image is still refused. Skipped only where the file system has no
// short names; on GitHub Actions (short temp directory) it must run.
func TestUpgradeAdmitsOwnImageThroughShortAlias(t *testing.T) {
	if os.Getenv("PENTRAIL_UPGRADE_SLEEPER") == "1" {
		time.Sleep(60 * time.Second)
		return
	}
	self := longPath(t, os.Args[0])
	short := shortPathOf(t, self)
	if strings.EqualFold(short, self) {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no 8.3 alias for %s on the CI runner; this case must run there", self)
		}
		t.Skip("no 8.3 short name for the test binary on this file system")
	}
	cmd := exec.Command(short, "-test.run=^TestUpgradeAdmitsOwnImageThroughShortAlias$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PENTRAIL_UPGRADE_SLEEPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-exited }) // this test's own child only
	servers := map[string]windows.Handle{}
	foreign := filepath.Join(t.TempDir(), "not-this-process.exe")
	if err := admitOwn(cmd.Process.Pid, foreign, []string{foreign}, "x", servers); err == nil || len(servers) != 0 {
		t.Fatalf("a process with another image was admitted: %v", err)
	}
	if err := admitOwn(cmd.Process.Pid, self, []string{self}, "x", servers); err != nil || len(servers) != 1 {
		t.Fatalf("own process started as %s not admitted: %v", short, err)
	}
	cleanupOwnServers(t.TempDir(), []string{self}, servers)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup did not end the admitted process")
	}
}

func shortPathOf(t *testing.T, p string) string {
	t.Helper()
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		t.Fatalf("short path of %s: %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}
