//go:build sqlcipher

package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Another process (pentrail serve/report/backup) holding the write lock for
// longer than SQLite's 5 s busy_timeout must PAUSE capture, not fail it. Before
// the fix the write failed with "database is locked", the error was sticky (all
// later writes failed too) and the session server killed the user's shell.
func TestCaptureSurvivesLockHeldByAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.db")
	key := []byte("lock-test-key")
	st, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.StartSession("bash", "h", "v")
	if err != nil {
		t.Fatal(err)
	}
	if e := st.WriteRaw(id, 0, 0, []byte("before\n")); e != nil {
		t.Fatal(e)
	}

	other, err := openDB(path, key) // independent connection, like a second process
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := other.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO capture_events(session_id,ts,recording,byte_offset) VALUES(?,?,?,?)`, id, 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() { time.Sleep(6 * time.Second); tx.Commit(); close(released) }()

	start := time.Now()
	if e := st.WriteRaw(id, 1, 7, []byte("during\n")); e != nil {
		t.Fatalf("capture failed while another process held the lock: %v", e)
	}
	<-released
	if waited := time.Since(start); waited < 5*time.Second {
		t.Fatalf("write did not actually contend for the lock (waited %v)", waited)
	}
	st.WriteCommand(Command{SessionID: id, Index: 0, Command: "echo", Complete: true})
	if e := st.WriteRaw(id, 2, 14, []byte("after\n")); e != nil {
		t.Fatalf("store stayed broken after the lock was released: %v", e)
	}
	if e := st.WriteError(); e != nil {
		t.Fatalf("sticky write error after recovery: %v", e)
	}
	data, missing, err := st.ReadRange(id, 0, 20)
	if err != nil || missing != 0 || string(data) != "before\nduring\nafter\n" {
		t.Fatalf("offsets corrupted by retries: data=%q missing=%d err=%v", data, missing, err)
	}
}
