//go:build linux

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Codex iteration 03, finding 3: a REAL kill (SIGKILL of a separate process)
// at each point of the cleanup protocol, then a fresh process reopens the
// database. Before this iteration a kill after the rename left
// .pentrail-cleanup-* on disk while the database said "clean".

const killKey = "kill-test-key"

// TestHelperCleanupKill runs in a child process only.
func TestHelperCleanupKill(t *testing.T) {
	db := os.Getenv("PENTRAIL_KILL_DB")
	if db == "" {
		t.Skip("helper process only")
	}
	stage, swap := os.Getenv("PENTRAIL_KILL_STAGE"), os.Getenv("PENTRAIL_KILL_SWAP")
	st, err := Open(db, []byte(killKey))
	if err != nil {
		t.Fatal(err)
	}
	cleanupHook = func(s, dir, name string) {
		if s == "verified" && swap != "" {
			// the name is swapped after our checks, before the rename
			if err := os.Rename(swap, filepath.Join(dir, name)); err != nil {
				os.Exit(4)
			}
		}
		if s == stage {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	}
	st.IngestArtifacts(1)
	os.Exit(3) // the kill point was never reached
}

type killEnv struct {
	t                *testing.T
	db, dir, p, base string
	orig             []byte
}

func newKillEnv(t *testing.T) *killEnv {
	base := t.TempDir()
	e := &killEnv{t: t, base: base, db: filepath.Join(base, "k.db"), dir: filepath.Join(base, "scans")}
	if err := os.Mkdir(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e.p = filepath.Join(e.dir, "nmap.xml")
	e.orig = []byte(`<nmaprun><host><address addr="10.5.5.5" addrtype="ipv4"/></host></nmaprun>`)
	mustWrite(t, e.p, e.orig)
	st, err := Open(e.db, []byte(killKey))
	if err != nil {
		t.Fatal(err)
	}
	artifactRow(t, st, 0, "nmap", e.p)
	crashState(t, st, e.p, e.orig) // imported, cleanup pending
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *killEnv) killAt(stage, swap string) {
	e.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCleanupKill$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PENTRAIL_KILL_DB="+e.db, "PENTRAIL_KILL_STAGE="+stage, "PENTRAIL_KILL_SWAP="+swap)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		e.t.Fatalf("helper not killed: %v %s", err, out)
	}
	ws := ee.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		e.t.Fatalf("helper did not die by SIGKILL at %q: %v %s", stage, err, out)
	}
}

func (e *killEnv) reopen() (*Store, ArtifactInfo) {
	e.t.Helper()
	st, err := Open(e.db, []byte(killKey))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { st.Close() })
	if _, err := st.IngestArtifacts(1); err != nil {
		e.t.Fatal(err)
	}
	return st, artifactByPath(e.t, st, e.p)
}

func quarantined(t *testing.T, dirs ...string) []string { return quarantineLeftovers(t, dirs...) }

func (e *killEnv) wantClean(a ArtifactInfo) {
	e.t.Helper()
	if exists(e.p) && readOrEmpty(e.p) == string(e.orig) {
		e.t.Fatal("imported plaintext original still on disk")
	}
	if l := quarantined(e.t, e.dir); len(l) != 0 {
		e.t.Fatalf("untracked quarantine copy left on disk: %v", l)
	}
	if a.CleanupPending || a.Quarantine != "" || a.CleanupDetail != "" {
		e.t.Fatalf("state not clean: %+v", a)
	}
}

func TestCleanupKilledAtEveryStep(t *testing.T) {
	t.Run("before the quarantine record", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("verified", "")
		if readOrEmpty(e.p) != string(e.orig) {
			t.Fatal("precondition: nothing may have changed yet")
		}
		_, a := e.reopen()
		e.wantClean(a)
	})
	t.Run("after the record, before the rename", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("intent", "")
		if readOrEmpty(e.p) != string(e.orig) || len(quarantined(t, e.dir)) != 0 {
			t.Fatal("precondition: record written, file not yet renamed")
		}
		_, a := e.reopen()
		e.wantClean(a)
	})
	t.Run("after the rename", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("quarantined", "")
		if exists(e.p) || len(quarantined(t, e.dir)) != 1 {
			t.Fatal("precondition: the file must sit under the quarantine name")
		}
		_, a := e.reopen()
		e.wantClean(a)
	})
	t.Run("after the rename, tool wrote a new file under the old name", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("quarantined", "")
		mustWrite(t, e.p, []byte("<nmaprun>NEW SCAN</nmaprun>"))
		_, a := e.reopen()
		if readOrEmpty(e.p) != "<nmaprun>NEW SCAN</nmaprun>" {
			t.Fatal("the new file under the old name was touched")
		}
		if l := quarantined(t, e.dir); len(l) != 0 {
			t.Fatalf("imported original left in quarantine: %v", l)
		}
		if a.CleanupPending || a.Quarantine != "" {
			t.Fatalf("state: %+v", a)
		}
	})
	t.Run("after unlink, before the record was cleared", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("unlinked", "")
		_, a := e.reopen()
		e.wantClean(a)
	})
	t.Run("a foreign file was captured by the rename", func(t *testing.T) {
		e := newKillEnv(t)
		foreign := filepath.Join(e.base, "users-file.xml")
		mustWrite(t, foreign, []byte("<nmaprun>USER'S OWN</nmaprun>"))
		e.killAt("quarantined", foreign)
		_, a := e.reopen()
		if readOrEmpty(e.p) != "<nmaprun>USER'S OWN</nmaprun>" {
			t.Fatalf("foreign file not restored under its name: %q", readOrEmpty(e.p))
		}
		if l := quarantined(t, e.dir); len(l) != 0 {
			t.Fatalf("leftovers: %v", l)
		}
		if a.CleanupPending || a.Quarantine != "" || !a.Problem() || !strings.Contains(a.CleanupDetail, "restored") {
			t.Fatalf("restore not reported: %+v", a)
		}
	})
	t.Run("foreign file captured and the old name re-used: nothing overwritten", func(t *testing.T) {
		e := newKillEnv(t)
		foreign := filepath.Join(e.base, "users-file.xml")
		mustWrite(t, foreign, []byte("<nmaprun>USER'S OWN</nmaprun>"))
		e.killAt("quarantined", foreign)
		mustWrite(t, e.p, []byte("third"))
		_, a := e.reopen()
		l := quarantined(t, e.dir)
		if readOrEmpty(e.p) != "third" || len(l) != 1 || readOrEmpty(l[0]) != "<nmaprun>USER'S OWN</nmaprun>" {
			t.Fatalf("a file was overwritten or lost: name=%q quarantine=%v", readOrEmpty(e.p), l)
		}
		if !a.CleanupPending || a.Quarantine == "" || !strings.Contains(a.CleanupDetail, l[0]) {
			t.Fatalf("left-behind file not tracked and reported: %+v", a)
		}
	})
	t.Run("after the rename, parent directory replaced", func(t *testing.T) {
		e := newKillEnv(t)
		e.killAt("quarantined", "")
		moved := e.dir + ".moved"
		if err := os.Rename(e.dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(e.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, a := e.reopen()
		l := quarantined(t, moved)
		if len(l) != 1 || readOrEmpty(l[0]) != string(e.orig) {
			t.Fatalf("quarantined copy in the moved directory touched: %v", l)
		}
		if !a.CleanupPending || a.Quarantine == "" || !a.Problem() || !strings.Contains(a.CleanupDetail, "moved directory") {
			t.Fatalf("not reported as unresolved: %+v", a)
		}
		// moved back: the next pass finishes the job
		os.Remove(e.dir)
		if err := os.Rename(moved, e.dir); err != nil {
			t.Fatal(err)
		}
		st2, err := Open(e.db, []byte(killKey))
		if err != nil {
			t.Fatal(err)
		}
		defer st2.Close()
		if _, err := st2.IngestArtifacts(1); err != nil {
			t.Fatal(err)
		}
		e.wantClean(artifactByPath(t, st2, e.p))
	})
}
