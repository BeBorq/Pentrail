package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func artifactRow(t *testing.T, st *Store, cmd int64, tool, path string) {
	t.Helper()
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1,1)`)
	db.Exec(`INSERT OR IGNORE INTO commands(session_id, cmd_index, command, complete) VALUES(1,?,?,1)`, cmd, tool)
	if _, e := db.Exec(`INSERT INTO command_artifacts(session_id, cmd_index, tool, path, finalized) VALUES(1,?,?,?,1)`, cmd, tool, path); e != nil {
		t.Fatal(e)
	}
}

func artifactByPath(t *testing.T, st *Store, path string) ArtifactInfo {
	t.Helper()
	all, err := st.ListArtifacts(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.Path == path {
			return a
		}
	}
	t.Fatalf("artifact %s not listed", path)
	return ArtifactInfo{}
}

func exists(p string) bool { _, e := os.Lstat(p); return e == nil }

// Setup helpers: every setup step is checked, so a test never blames the
// importer for something its own setup failed to do (Codex iteration 02).
func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("setup: write %s: %v", p, err)
	}
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatalf("setup: remove %s: %v", p, err)
	}
}

// trySymlink creates link -> target. It returns false (and the caller skips
// only the symlink case) when this system does not let an unprivileged user
// create symlinks (Windows without Developer Mode: "A required privilege is
// not held by the client"); any other error fails the test. Privileges are
// never raised.
func trySymlink(t *testing.T, target, link string) bool {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return true
	}
	if symlinkUnavailable(err) {
		t.Logf("symlinks unavailable here, case not run: %v", err)
		return false
	}
	t.Fatalf("setup: symlink %s -> %s: %v", link, target, err)
	return false
}

// #2: two concatenated JSON documents used to be imported as the first one and
// the whole original deleted. Now: not imported, original kept, reason stored,
// and the other artifacts of the batch are still processed.
func TestConcatenatedJSONIsNotImportedAsComplete(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "ffuf-bad.json")
	good := filepath.Join(dir, "ffuf-good.json")
	mustWrite(t, bad, []byte(`{"results":[{"url":"http://t/one","status":200}]}{"results":[{"url":"http://t/two","status":200}]}`))
	mustWrite(t, good, []byte(`{"results":[{"url":"http://t/three","status":200}]}`))
	artifactRow(t, st, 0, "ffuf", bad)
	artifactRow(t, st, 1, "ffuf", good)

	n, err := st.IngestArtifacts(1)
	if err != nil || n != 1 {
		t.Fatalf("ingest n=%d err=%v (want the good file imported, no batch error)", n, err)
	}
	if !exists(bad) {
		t.Fatal("original of an invalid document was deleted")
	}
	a := artifactByPath(t, st, bad)
	if a.State != ArtRejected || a.Detail == "" || !a.Problem() {
		t.Fatalf("invalid document state not recorded: %+v", a)
	}
	var content []byte
	st.DB().QueryRow(`SELECT content FROM command_artifacts WHERE path=?`, bad).Scan(&content)
	if content != nil {
		t.Fatal("first document of an invalid file was stored as if complete")
	}
	if g := artifactByPath(t, st, good); g.State != ArtImported || exists(good) {
		t.Fatalf("good artifact: %+v exists=%v", g, exists(good))
	}
	// unchanged file: not re-parsed/re-reported on every tick
	if n, err := st.IngestArtifacts(1); err != nil || n != 0 {
		t.Fatalf("re-ingest: %d %v", n, err)
	}
}

// #2: a recovered prefix is imported but marked incomplete in the stored
// state AND on every entity derived from it.
func TestPartialImportIsMarkedAndVisible(t *testing.T) {
	st := openTemp(t)
	p := filepath.Join(t.TempDir(), "nmap.xml")
	mustWrite(t, p, []byte(`<nmaprun><host><address addr="10.9.9.1" addrtype="ipv4"/></host><host><address addr="10.9.9.2"`))
	artifactRow(t, st, 0, "nmap", p)
	if n, err := st.IngestArtifacts(1); err != nil || n != 1 {
		t.Fatalf("ingest %d %v", n, err)
	}
	a := artifactByPath(t, st, p)
	if a.State != ArtImportedPartial || !a.Partial || !a.Problem() || !strings.Contains(a.Detail, "is NOT complete") {
		t.Fatalf("partial import not marked: %+v", a)
	}
	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	var details string
	st.DB().QueryRow(`SELECT COALESCE(details,'') FROM entities WHERE type='host' AND value='10.9.9.1'`).Scan(&details)
	if !strings.Contains(details, "incomplete") {
		t.Fatalf("entity from a partial artifact presented as complete: %q", details)
	}
}

// #5: >64 MiB, missing and non-regular files are left alone, never block the
// others, and the reason is stored.
func TestSkippedArtifactReasonIsPersisted(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	big := filepath.Join(dir, "nuclei-big.jsonl")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxArtifactBytes + 1); err != nil { // 67 108 865 B, sparse
		t.Fatal(err)
	}
	f.Close()
	missing := filepath.Join(dir, "ffuf-missing.json")
	notFile := filepath.Join(dir, "nmap-dir.xml")
	if err := os.Mkdir(notFile, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "nmap-link.xml")
	target := filepath.Join(dir, "elsewhere.xml")
	mustWrite(t, target, []byte("<nmaprun></nmaprun>"))
	haveLink := trySymlink(t, target, link)
	good := filepath.Join(dir, "nmap-good.xml")
	mustWrite(t, good, []byte(`<nmaprun><host><address addr="10.1.1.1" addrtype="ipv4"/></host></nmaprun>`))
	artifactRow(t, st, 0, "nuclei", big)
	artifactRow(t, st, 1, "ffuf", missing)
	artifactRow(t, st, 2, "nmap", notFile)
	if haveLink {
		artifactRow(t, st, 3, "nmap", link)
	}
	artifactRow(t, st, 4, "nmap", good)

	n, err := st.IngestArtifacts(1)
	if err != nil || n != 1 {
		t.Fatalf("ingest n=%d err=%v", n, err)
	}
	check := func(p, state, detailPart string) {
		a := artifactByPath(t, st, p)
		if a.State != state || !strings.Contains(a.Detail, detailPart) || !a.Problem() {
			t.Fatalf("%s: got %+v, want state %s with %q", filepath.Base(p), a, state, detailPart)
		}
	}
	check(big, ArtTooLarge, "67108865")
	check(missing, ArtMissing, "does not exist")
	check(notFile, ArtUnsafe, "regular file") // same on Linux and Windows
	if haveLink {
		check(link, ArtUnsafe, "link")
		if !exists(link) {
			t.Fatal("a symlink was deleted")
		}
	}
	if !exists(big) || !exists(target) || !exists(notFile) {
		t.Fatal("a skipped file (or a symlink target) was deleted")
	}
	if exists(good) || artifactByPath(t, st, good).State != ArtImported {
		t.Fatal("a valid artifact in the same batch was not imported")
	}
}

// #4: the import is committed with cleanup_pending=1 and the identity of the
// ORIGINAL bytes. A crash before deletion leaves that state; the next call
// verifies and deletes.
func TestCleanupResumesAfterCrashWindow(t *testing.T) {
	st := openTemp(t)
	p := filepath.Join(t.TempDir(), "nmap.xml")
	orig := []byte(`<nmaprun><host><address addr="10.2.2.2" addrtype="ipv4"/></host></nmaprun>`)
	mustWrite(t, p, orig)
	artifactRow(t, st, 0, "nmap", p)
	crashState(t, st, p, orig)
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if exists(p) {
		t.Fatal("plaintext left behind after the interrupted cleanup")
	}
	if a := artifactByPath(t, st, p); a.CleanupPending || a.CleanupDetail != "" {
		t.Fatalf("cleanup state not cleared: %+v", a)
	}
}

// crashState reproduces what a crash right after the import commit leaves.
func crashState(t *testing.T, st *Store, p string, orig []byte) {
	t.Helper()
	f, err := openArtifact(p)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fileIdentity(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(orig)
	if _, err := st.DB().Exec(`UPDATE command_artifacts SET ingested=1, content=?, state=?, src_sha256=?, src_size=?, src_identity=?, cleanup_pending=1 WHERE path=?`,
		orig, ArtImported, hex.EncodeToString(sum[:]), len(orig), id, p); err != nil {
		t.Fatal(err)
	}
}

// #4: what sits at the path after the import is deleted only if it is provably
// the imported original — not a rewritten file, not a symlink, not its target.
// Limit: a NEW file with byte-identical content that the filesystem gives the
// same inode number is indistinguishable (device, inode, size and SHA-256 all
// match) and is deleted; it holds only bytes already stored encrypted.
func TestCleanupNeverDeletesSubstitutedFile(t *testing.T) {
	for _, mode := range []string{"rewritten", "replaced", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			st := openTemp(t)
			dir := t.TempDir()
			p := filepath.Join(dir, "nmap.xml")
			orig := []byte(`<nmaprun><host><address addr="10.3.3.3" addrtype="ipv4"/></host></nmaprun>`)
			mustWrite(t, p, orig)
			artifactRow(t, st, 0, "nmap", p)
			crashState(t, st, p, orig)
			sentinel := filepath.Join(dir, "users-own-file.txt")
			mustWrite(t, sentinel, []byte("not pentrail's"))
			switch mode {
			case "rewritten": // same inode, different bytes
				mustWrite(t, p, []byte(`<nmaprun><host><address addr="10.3.3.4" addrtype="ipv4"/></host></nmaprun>`))
			case "replaced": // a different file (same size, other bytes) under the same name
				mustRemove(t, p)
				mustWrite(t, p, []byte(strings.Replace(string(orig), "10.3.3.3", "10.3.3.9", 1)))
			case "symlink":
				mustRemove(t, p)
				if !trySymlink(t, sentinel, p) {
					t.Skip("symlinks unavailable without raising privileges")
				}
			}
			if !exists(p) {
				t.Fatal("setup: nothing at the artifact path before cleanup")
			}
			if _, err := st.IngestArtifacts(1); err != nil {
				t.Fatal(err)
			}
			if !exists(p) || !exists(sentinel) {
				t.Fatal("a file that is not the imported original was deleted")
			}
			a := artifactByPath(t, st, p)
			if a.CleanupPending || !strings.Contains(a.CleanupDetail, "not deleted") || !a.Problem() {
				t.Fatalf("mismatch not reported: %+v", a)
			}
		})
	}
}

// #4: a deletion that fails (here: immutable file) keeps cleanup_pending, is
// reported in the stored state, is retried, and succeeds once possible.
func TestCleanupFailureIsRetriedAndVisible(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chattr +i needs root")
	}
	if _, err := exec.LookPath("chattr"); err != nil {
		t.Skip("chattr not available")
	}
	st := openTemp(t)
	p := filepath.Join(t.TempDir(), "nmap.xml")
	mustWrite(t, p, []byte(`<nmaprun><host><address addr="10.4.4.4" addrtype="ipv4"/></host></nmaprun>`))
	if out, err := exec.Command("chattr", "+i", p).CombinedOutput(); err != nil {
		t.Skipf("filesystem does not support chattr +i: %s", out)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", p).Run() })
	artifactRow(t, st, 0, "nmap", p)

	if n, err := st.IngestArtifacts(1); err != nil || n != 1 {
		t.Fatalf("ingest %d %v", n, err)
	}
	a := artifactByPath(t, st, p)
	if !exists(p) || !a.CleanupPending || !strings.Contains(a.CleanupDetail, "will retry") || !a.Problem() {
		t.Fatalf("failed deletion not persisted: exists=%v %+v", exists(p), a)
	}
	if n, err := st.IngestArtifacts(1); err != nil || n != 0 {
		t.Fatalf("retry must not re-import: %d %v", n, err)
	}
	exec.Command("chattr", "-i", p).Run()
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if exists(p) {
		t.Fatal("deletion was not retried")
	}
	if a := artifactByPath(t, st, p); a.CleanupPending || a.CleanupDetail != "" {
		t.Fatalf("state after successful retry: %+v", a)
	}
}

// Rows imported by older versions carry no checksum of the original; a file
// still at the path is reported, never deleted on a guess.
func TestLegacyImportedRowsAreReportedNotDeleted(t *testing.T) {
	st := openTemp(t)
	p := filepath.Join(t.TempDir(), "nmap.xml")
	mustWrite(t, p, []byte("<nmaprun></nmaprun>"))
	artifactRow(t, st, 0, "nmap", p)
	st.DB().Exec(`UPDATE command_artifacts SET ingested=1, content=?, state='' WHERE path=?`, []byte("<nmaprun></nmaprun>"), p)
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if !exists(p) {
		t.Fatal("legacy file deleted without proof it is the original")
	}
	if a := artifactByPath(t, st, p); a.State != ArtLegacyUnchecked || !a.Problem() {
		t.Fatalf("legacy plaintext not reported: %+v", a)
	}
}
