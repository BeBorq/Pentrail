//go:build linux

package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Codex iteration 02, finding 4: a SECOND Store of the same database opened
// in the SAME process while the first is alive. PrepareDB/protectSideFiles
// open and close extra descriptors of the database and -shm; on POSIX that
// drops every fcntl lock this process holds on them — including the first
// Store's. A helper process then resets the WAL index under the first Store.
func TestSecondOpenInSameProcessKeepsFirstStoresLocks(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	first, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	id, _ := first.StartSession("bash", "h", "v")
	var off int64
	write := func(st *Store, i int) {
		line := []byte(fmt.Sprintf("line-%04d\n", i))
		if e := st.WriteRaw(id, int64(i), off, line); e != nil {
			t.Fatalf("write %d: %v", i, e)
		}
		off += int64(len(line))
	}
	for i := 0; i < 5; i++ {
		write(first, i)
	}
	if !holdsLockOn(t, db+"-shm") {
		t.Fatal("precondition: first Store holds no lock on -shm")
	}

	second, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Logf("second Open refused: %v", err)
		if !strings.Contains(err.Error(), "already open in this process") {
			t.Fatalf("second Open failed for another reason: %v", err)
		}
	}
	if !holdsLockOn(t, db+"-shm") {
		lockLost(t, "the second Open dropped the first Store's lock on -shm: other processes may reset the WAL index under it")
	}
	if second != nil {
		if v := second.integrityOK(); v != "ok" {
			t.Fatalf("second integrity_check: %s", v)
		}
		// closing the second Store must not drop the first one's locks either
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
		second = nil
		if !holdsLockOn(t, db+"-shm") {
			lockLost(t, "closing the second Store dropped the first Store's lock on -shm")
		}
	}
	for i := 0; i < 30; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperOpenAndClose$")
		cmd.Env = append(os.Environ(), "PENTRAIL_WAL_HELPER="+db)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("helper process: %v %s", err, out)
		}
		for k := 0; k < 5; k++ {
			write(first, 5+i*5+k)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := first.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	data, missing, err := first.ReadRange(id, 0, off)
	if err != nil || missing != 0 || int64(len(data)) != off || !strings.HasSuffix(string(data), "line-0154\n") {
		t.Fatalf("session data damaged: len=%d/%d missing=%d err=%v", len(data), off, missing, err)
	}
	if v := first.integrityOK(); v != "ok" {
		t.Fatalf("integrity_check: %s", v)
	}
	for _, side := range []string{db, db + "-wal", db + "-shm"} {
		fi, err := os.Stat(side)
		if err != nil {
			t.Errorf("%s removed under the running Store (its WAL now lives in a deleted file): %v", side, err)
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v (want 0600)", side, fi.Mode().Perm())
		}
	}
	// The real test of durability: everything is there after a restart.
	if second != nil {
		second.Close()
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	data, missing, err = again.ReadRange(id, 0, off)
	if err != nil || missing != 0 || int64(len(data)) != off {
		t.Fatalf("after reopen: %d of %d bytes, missing=%d err=%v — data written after the second Open was lost", len(data), off, missing, err)
	}
}

// lockLost fails, unless PENTRAIL_SHOW_DAMAGE=1 asks to continue and show
// what the lost lock leads to (used for the before/after evidence).
func lockLost(t *testing.T, msg string) {
	t.Helper()
	if os.Getenv("PENTRAIL_SHOW_DAMAGE") == "1" {
		t.Log(msg)
		return
	}
	t.Fatal(msg)
}

// An artifact path that names the database itself (or -wal/-shm) is never
// opened: the open/close alone would drop this process's SQLite locks.
func TestArtifactPathPointingAtTheDatabase(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	st, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.StartSession("bash", "h", "v"); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{db, db + "-wal", db + "-shm"} {
		artifactRow(t, st, int64(i), "nmap", p)
	}
	if _, err := st.IngestArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if !holdsLockOn(t, db+"-shm") {
		t.Fatal("ingest dropped the Store's lock on -shm")
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if a := artifactByPath(t, st, p); a.State != ArtUnsafe || !exists(p) {
			t.Fatalf("%s: %+v", p, a)
		}
	}
}
