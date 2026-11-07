//go:build linux

package store

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const userScan = "<nmaprun>user's NEW unarchived scan</nmaprun>"

func quarantineLeftovers(t *testing.T, dirs ...string) []string {
	t.Helper()
	var left []string
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(d, ".pentrail-cleanup-*"))
		left = append(left, m...)
	}
	return left
}

func readOrEmpty(p string) string { b, _ := os.ReadFile(p); return string(b) }

// Codex iteration 02, finding 5: substitutions DURING the cleanup, at exact
// points (no timing luck). Before this iteration the "after checks" case
// deleted the user's new file (see TestReproSwapRightBeforeUnlink in the
// report: open .../nmap.xml: no such file or directory).
func TestCleanupSubstitutionDuringCleanup(t *testing.T) {
	orig := []byte(`<nmaprun><host><address addr="10.7.7.7" addrtype="ipv4"/></host></nmaprun>`)
	type env struct {
		t             *testing.T
		dir, p, users string
		moved         string // parent directory after a rename
	}
	cases := []struct {
		name  string
		setup func(e *env)                     // before IngestArtifacts
		hook  func(e *env, stage, d, n string) // during cleanup
		check func(e *env, a ArtifactInfo)
	}{
		{
			name: "name swapped after the pre-check (before quarantine)",
			hook: func(e *env, stage, d, n string) {
				if stage == "verified" {
					if err := os.Rename(e.users, e.p); err != nil {
						e.t.Fatalf("setup: swap: %v", err)
					}
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != userScan {
					e.t.Fatalf("user's file not back under its name: %q", readOrEmpty(e.p))
				}
				if a.CleanupPending || !strings.Contains(a.CleanupDetail, "not deleted") {
					e.t.Fatalf("mismatch not recorded: %+v", a)
				}
			},
		},
		{
			name: "name swapped right before the deletion (the iteration-1 repro)",
			hook: func(e *env, stage, d, n string) {
				if stage == "before-unlink" {
					if err := os.Rename(e.users, e.p); err != nil {
						e.t.Fatalf("setup: swap: %v", err)
					}
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != userScan {
					e.t.Fatalf("user's file deleted or changed: %q", readOrEmpty(e.p))
				}
				if a.CleanupPending || a.CleanupDetail != "" {
					e.t.Fatalf("original (already quarantined and verified) should be removed: %+v", a)
				}
			},
		},
		{
			name: "tool writes a new file under the name while quarantined",
			hook: func(e *env, stage, d, n string) {
				if stage == "quarantined" {
					mustWrite(e.t, e.p, []byte(userScan))
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != userScan || a.CleanupPending || a.CleanupDetail != "" {
					e.t.Fatalf("new file %q, state %+v", readOrEmpty(e.p), a)
				}
			},
		},
		{
			name: "swapped AND the name re-used: nothing overwritten on restore",
			hook: func(e *env, stage, d, n string) {
				switch stage {
				case "verified":
					if err := os.Rename(e.users, e.p); err != nil {
						e.t.Fatalf("setup: swap: %v", err)
					}
				case "quarantined":
					mustWrite(e.t, e.p, []byte("third file"))
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != "third file" {
					e.t.Fatalf("file created under the name was overwritten: %q", readOrEmpty(e.p))
				}
				left := quarantineLeftovers(e.t, e.dir)
				if len(left) != 1 || readOrEmpty(left[0]) != userScan {
					e.t.Fatalf("user's swapped file lost: %v", left)
				}
				if !strings.Contains(a.CleanupDetail, left[0]) || !a.Problem() {
					e.t.Fatalf("where the file was left is not recorded: %+v", a)
				}
				os.Remove(left[0]) // test cleanup only
			},
		},
		{
			name: "parent directory replaced during cleanup",
			hook: func(e *env, stage, d, n string) {
				if stage == "verified" {
					e.moved = e.dir + ".moved"
					if err := os.Rename(e.dir, e.moved); err != nil {
						e.t.Fatalf("setup: move dir: %v", err)
					}
					if err := os.Mkdir(e.dir, 0o700); err != nil {
						e.t.Fatal(err)
					}
					mustWrite(e.t, e.p, orig) // same bytes, different file
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != string(orig) {
					e.t.Fatal("file in the NEW directory was deleted")
				}
				if exists(filepath.Join(e.moved, "nmap.xml")) {
					e.t.Fatal("verified original (in the moved directory) left behind")
				}
				if len(quarantineLeftovers(e.t, e.dir, e.moved)) != 0 {
					e.t.Fatal("quarantine leftovers")
				}
				os.RemoveAll(e.moved)
			},
		},
		{
			name: "parent directory replaced before cleanup",
			setup: func(e *env) {
				e.moved = e.dir + ".moved"
				if err := os.Rename(e.dir, e.moved); err != nil {
					e.t.Fatal(err)
				}
				if err := os.Mkdir(e.dir, 0o700); err != nil {
					e.t.Fatal(err)
				}
				mustWrite(e.t, e.p, orig)
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) != string(orig) || !exists(filepath.Join(e.moved, "nmap.xml")) {
					e.t.Fatal("a file was deleted although the path now names another file")
				}
				if a.CleanupPending || !strings.Contains(a.CleanupDetail, "inode") {
					e.t.Fatalf("mismatch not recorded: %+v", a)
				}
				os.RemoveAll(e.moved)
			},
		},
		{
			name: "file held open by another process: retried, not deleted now",
			// e.g. the tool (or an editor) still has it open: no write lease
			// is granted, nothing is renamed or deleted
			setup: func(e *env) {
				f, err := os.OpenFile(e.p, os.O_WRONLY, 0)
				if err != nil {
					e.t.Fatal(err)
				}
				e.t.Cleanup(func() { f.Close() })
				holder = f
			},
			check: func(e *env, a ArtifactInfo) {
				if readOrEmpty(e.p) == "" || !a.CleanupPending || !strings.Contains(a.CleanupDetail, "is open") {
					e.t.Fatalf("open file deleted or not retried: exists=%v %+v", exists(e.p), a)
				}
				if len(quarantineLeftovers(e.t, e.dir)) != 0 {
					e.t.Fatal("not restored under its name")
				}
			},
		},
		{
			name: "hard link elsewhere",
			setup: func(e *env) {
				if err := os.Link(e.p, filepath.Join(e.dir, "copy.xml")); err != nil {
					e.t.Fatal(err)
				}
			},
			check: func(e *env, a ArtifactInfo) {
				if !exists(e.p) || !strings.Contains(a.CleanupDetail, "hard links") {
					e.t.Fatalf("hard-linked file: exists=%v %+v", exists(e.p), a)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder = nil
			st := openTemp(t)
			base := t.TempDir()
			e := &env{t: t, dir: filepath.Join(base, "scans")}
			if err := os.Mkdir(e.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			e.p = filepath.Join(e.dir, "nmap.xml")
			e.users = filepath.Join(base, "users-new-scan.xml")
			mustWrite(t, e.p, orig)
			mustWrite(t, e.users, []byte(userScan))
			artifactRow(t, st, 0, "nmap", e.p)
			crashState(t, st, e.p, orig)
			if tc.setup != nil {
				tc.setup(e)
			}
			if tc.hook != nil {
				cleanupHook = func(stage, d, n string) { tc.hook(e, stage, d, n) }
			}
			defer func() { cleanupHook = nil }()
			if _, err := st.IngestArtifacts(1); err != nil {
				t.Fatal(err)
			}
			cleanupHook = nil
			tc.check(e, artifactByPath(t, st, e.p))
			if tc.name == "file held open by another process: retried, not deleted now" {
				holder.Close()
				if _, err := st.IngestArtifacts(1); err != nil {
					t.Fatal(err)
				}
				if exists(e.p) || artifactByPath(t, st, e.p).CleanupPending {
					t.Fatal("not deleted on retry after the other process closed it")
				}
			}
		})
	}
}

var holder *os.File

// A FIFO planted under an artifact name used to block the importer forever.
func TestFIFOArtifactDoesNotBlockImport(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "nmap.xml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "ffuf.json")
	mustWrite(t, good, []byte(`{"results":[]}`))
	artifactRow(t, st, 0, "nmap", fifo)
	artifactRow(t, st, 1, "ffuf", good)
	done := make(chan error, 1)
	go func() { _, err := st.IngestArtifacts(1); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("importer blocked on a FIFO")
	}
	if a := artifactByPath(t, st, fifo); a.State != ArtUnsafe || !exists(fifo) {
		t.Fatalf("FIFO: %+v", a)
	}
	if exists(good) {
		t.Fatal("other artifact not imported")
	}
}
