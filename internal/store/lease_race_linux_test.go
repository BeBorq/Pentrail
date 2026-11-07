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

// Codex iteration 03, finding 2: the write lease must last until the
// deletion. A writer that opens the quarantined file after the verification
// (here: right before unlink) and appends new, never-imported bytes must not
// lose them. Before the fix the lease was released when the check returned,
// so the open succeeded at once and the file was then unlinked.
func TestLeaseHeldUntilUnlink(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "nmap.xml")
	orig := []byte(`<nmaprun><host><address addr="10.8.8.8" addrtype="ipv4"/></host></nmaprun>`)
	mustWrite(t, p, orig)
	artifactRow(t, st, 0, "nmap", p)
	crashState(t, st, p, orig)
	const extra = "<!-- NEW UNARCHIVED SCAN BYTES -->"
	wrote := make(chan error, 1)
	cleanupHook = func(stage, d, n string) {
		if stage != "before-unlink" {
			return
		}
		target := filepath.Join(d, n)
		go func() { // a concurrent writer (another thread; with a lease its open waits)
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				wrote <- err
				return
			}
			_, err = f.WriteString(extra)
			f.Close()
			wrote <- err
		}()
		select { // let it either finish (no lease) or block (lease held)
		case err := <-wrote:
			wrote <- err
		case <-time.After(300 * time.Millisecond):
		}
	}
	defer func() { cleanupHook = nil }()
	start := time.Now()
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	cleanupHook = nil
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("cleanup blocked itself for %v", el)
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer never completed (lease not released)")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("file with new, never-imported bytes was deleted: %v", err)
	}
	if !strings.HasSuffix(string(b), extra) {
		t.Fatalf("new bytes not in the file kept under its name: %q", b)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".pentrail-cleanup-*")); len(m) != 0 {
		t.Fatalf("quarantine leftovers: %v", m)
	}
	a := artifactByPath(t, st, p)
	if !a.Problem() || a.CleanupDetail == "" {
		t.Fatalf("concurrent open not reported: %+v", a)
	}
	// next pass: the content changed, so it is never deleted
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if !exists(p) {
		t.Fatal("changed file deleted on retry")
	}
}

// Without a write lease (file of another owner, e.g. written via sudo; a
// filesystem without leases) there is no guarantee that the bytes deleted
// are the imported ones: the file is kept, under its own name, and that is
// recorded — never deleted on a hash alone.
func TestNoLeaseKeepsFile(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "nmap.xml")
	orig := []byte(`<nmaprun><host><address addr="10.8.8.9" addrtype="ipv4"/></host></nmaprun>`)
	mustWrite(t, p, orig)
	artifactRow(t, st, 0, "nmap", p)
	crashState(t, st, p, orig)
	old := setLease
	setLease = func(int) error { return syscall.EACCES }
	defer func() { setLease = old }()
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != string(orig) {
		t.Fatalf("file not kept under its name: %q %v", b, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".pentrail-cleanup-*")); len(m) != 0 {
		t.Fatalf("renamed although it cannot be deleted: %v", m)
	}
	a := artifactByPath(t, st, p)
	if a.CleanupPending || !strings.Contains(a.CleanupDetail, "lease") || !a.Problem() || a.Quarantine != "" {
		t.Fatalf("kept file not reported: %+v", a)
	}
}
