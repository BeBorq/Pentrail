//go:build linux

package store

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const walTestKey = "test-passphrase"

// holdsLockOn reports whether this process holds any POSIX lock on path.
func holdsLockOn(t *testing.T, path string) bool {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("/proc/locks")
	if err != nil {
		t.Skip("/proc/locks not available")
	}
	defer f.Close()
	ino := fmt.Sprintf(":%d", st.Ino)
	pid := fmt.Sprint(os.Getpid())
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		// "1: POSIX  ADVISORY  READ 1234 fd:01:5678 128 128"
		if len(fl) >= 6 && fl[1] == "POSIX" && fl[4] == pid && strings.HasSuffix(fl[5], ino) {
			return true
		}
	}
	return false
}

// Regression (found by the parallel-terminals test): Open protected -wal/-shm
// AFTER SQLite had opened them; closing that extra descriptor dropped
// SQLite's POSIX locks on -shm. The next process to open the database then
// believed nobody used the shared WAL index and reset it under the running
// session server — SIGBUS (the user's shell died) or a corrupted index.
func TestOpenKeepsSQLiteLockOnSharedMemory(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	st, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !holdsLockOn(t, db+"-shm") {
		t.Fatal("this process lost SQLite's lock on -shm after Open: other processes may reset the WAL index under it")
	}
	for _, side := range []string{db + "-wal", db + "-shm"} {
		if fi, err := os.Stat(side); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v err %v (want 0600)", side, fi.Mode().Perm(), err)
		}
	}
}

// Other processes (terminals, extract, the viewer) opening and closing the
// database must not disturb a session that keeps writing.
func TestOtherProcessesDoNotResetRunningSession(t *testing.T) {
	if os.Getenv("PENTRAIL_WAL_HELPER") != "" {
		return
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	st, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := st.StartSession("bash", "h", "v")
	var off int64
	write := func(i int) {
		line := []byte(fmt.Sprintf("line-%04d\n", i))
		if e := st.WriteRaw(id, int64(i), off, line); e != nil {
			t.Fatalf("write %d: %v", i, e)
		}
		off += int64(len(line))
	}
	for i := 0; i < 30; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperOpenAndClose$")
		cmd.Env = append(os.Environ(), "PENTRAIL_WAL_HELPER="+db)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("helper process: %v %s", err, out)
		}
		for k := 0; k < 5; k++ {
			write(i*5 + k)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := st.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	data, missing, err := st.ReadRange(id, 0, off)
	if err != nil || missing != 0 || int64(len(data)) != off || !strings.HasSuffix(string(data), "line-0149\n") {
		t.Fatalf("session data damaged: len=%d/%d missing=%d err=%v", len(data), off, missing, err)
	}
	if v := st.integrityOK(); v != "ok" {
		t.Fatalf("integrity_check: %s", v)
	}
}

func TestHelperOpenAndClose(t *testing.T) {
	db := os.Getenv("PENTRAIL_WAL_HELPER")
	if db == "" {
		t.Skip("helper process only")
	}
	st, err := Open(db, []byte(walTestKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListSessions(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func (s *Store) integrityOK() string {
	var v string
	if err := s.db.QueryRow("PRAGMA integrity_check").Scan(&v); err != nil {
		return err.Error()
	}
	return v
}
