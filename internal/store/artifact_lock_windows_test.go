//go:build windows

package store

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Codex iteration 02: a Windows cleanup retry test that needs neither
// symlinks nor chattr. Another process/handle (an editor, an indexer, the
// tool itself) keeps the file open WITHOUT delete sharing: the deletion fails
// with a sharing violation, cleanup_pending stays set with a visible reason,
// the file is not re-imported, and the next pass deletes it once released.
func TestCleanupRetriedWhileFileIsLockedByAnotherHandle(t *testing.T) {
	st := openTemp(t)
	p := filepath.Join(t.TempDir(), "nmap.xml")
	mustWrite(t, p, []byte(`<nmaprun><host><address addr="10.6.6.6" addrtype="ipv4"/></host></nmaprun>`))
	artifactRow(t, st, 0, "nmap", p)
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	// like a tool still holding its output: write access, shares read only
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("setup: open holder handle: %v", err)
	}
	released := false
	release := func() {
		if !released {
			windows.CloseHandle(h)
			released = true
		}
	}
	defer release()

	if n, err := st.IngestArtifacts(1); err != nil || n != 1 {
		t.Fatalf("ingest %d %v", n, err)
	}
	a := artifactByPath(t, st, p)
	if !exists(p) || !a.CleanupPending || !strings.Contains(a.CleanupDetail, "will retry") || !a.Problem() {
		t.Fatalf("failed deletion not persisted/visible: exists=%v %+v", exists(p), a)
	}
	if n, err := st.IngestArtifacts(1); err != nil || n != 0 {
		t.Fatalf("retry while still locked must not re-import: %d %v", n, err)
	}
	if !exists(p) || !artifactByPath(t, st, p).CleanupPending {
		t.Fatal("locked file vanished or pending state lost")
	}
	release()
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if exists(p) {
		t.Fatal("deletion was not retried after the handle was closed")
	}
	if a := artifactByPath(t, st, p); a.CleanupPending || a.CleanupDetail != "" || a.State != ArtImported {
		t.Fatalf("state after successful retry: %+v", a)
	}
}
