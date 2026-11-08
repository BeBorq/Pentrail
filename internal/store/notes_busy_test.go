package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// holdWriteLock opens a SECOND connection to the database, as another process
// (a recording session server) would, takes the write lock with BEGIN
// IMMEDIATE and writes a raw chunk in that transaction. It commits after hold;
// the returned channel reports the commit result.
func holdWriteLock(t *testing.T, path string, sid int64, chunk []byte, hold time.Duration) <-chan error {
	t.Helper()
	db, err := openDB(path, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	var off int64
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(byte_offset+length(data)),0) FROM raw_chunks WHERE session_id=?`, sid).Scan(&off); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data,redacted_bytes) VALUES(?,?,?,?,?,0)`, sid, 900, time.Now().UnixNano(), off, chunk); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(hold)
		_, err := conn.ExecContext(ctx, `COMMIT`)
		conn.Close()
		db.Close()
		done <- err
	}()
	return done
}

// A note change while another connection holds the write lock for longer than
// SQLite's busy timeout (5 s in the encrypted build, none in the plain build)
// used to fail at once with "database is locked" (GitHub Actions, Windows,
// TestNotesWrittenByAnotherProcessWhileRecording: TestHelperNotesWriter's
// CreateNote). It now waits, within a bounded window, for the lock and is
// written exactly once; the other writer's evidence is intact.
func TestNoteWriteWaitsForAnotherWritersLock(t *testing.T) {
	st := openTemp(t)
	sid, _ := notesSession(t, st)
	path := filepath.Join(filepath.Dir(st.path), "t.db")
	chunk := []byte("held-writer-chunk password=SyntheticHeld\n")
	done := holdWriteLock(t, path, sid, chunk, 6*time.Second)
	t0 := time.Now()
	n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0)}, "while locked", "token=SyntheticBusy1 body")
	waited := time.Since(t0)
	if cerr := <-done; cerr != nil {
		t.Fatalf("the lock holder's commit: %v", cerr)
	}
	if err != nil {
		t.Fatalf("note change failed while another writer held the lock (after %v): %v", waited.Round(time.Millisecond), err)
	}
	if waited < 5*time.Second {
		t.Fatalf("the note was written after %v, before the other writer released its lock", waited)
	}
	if n.Revision != 1 || n.Title != "while locked" || strings.Contains(n.Body, "SyntheticBusy1") || !strings.Contains(n.Body, "body") {
		t.Fatalf("note %+v", n)
	}
	var rows int
	if err := st.DB().QueryRow(`SELECT count(*) FROM notes WHERE session_id=?`, sid).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("notes rows: %d %v", rows, err)
	}
	got, err := st.GetNote(sid, n.ID)
	if err != nil || got.Revision != 1 || got.Body != n.Body {
		t.Fatalf("stored note %+v %v", got, err)
	}
	var data []byte
	if err := st.DB().QueryRow(`SELECT data FROM raw_chunks WHERE session_id=? AND seq=900`, sid).Scan(&data); err != nil || string(data) != string(chunk) {
		t.Fatalf("the other writer's chunk: %q %v", data, err)
	}
	// Updates and archiving wait the same way.
	done = holdWriteLock(t, path, sid, []byte("second-held-chunk\n"), 5500*time.Millisecond)
	u, err := st.UpdateNote(sid, n.ID, n.Revision, n.Title, "changed while locked")
	if cerr := <-done; cerr != nil || err != nil || u.Revision != 2 || u.Body != "changed while locked" {
		t.Fatalf("update while locked: %+v %v (holder %v)", u, err, cerr)
	}
	requireNotesIntegrity(t, st.DB())
}

// The wait is bounded: a lock that outlasts the window ends in the lock error
// and nothing is written. Conflicts are never retried.
func TestNoteWriteBusyWindowIsBounded(t *testing.T) {
	old := noteBusyWindow
	noteBusyWindow = 300 * time.Millisecond
	defer func() { noteBusyWindow = old }()
	st := openTemp(t)
	sid, _ := notesSession(t, st)
	n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorSession}, "base", "base")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(st.path), "t.db")
	done := holdWriteLock(t, path, sid, []byte("long-held-chunk\n"), 7*time.Second)
	t0 := time.Now()
	_, err = st.UpdateNote(sid, n.ID, n.Revision, "x", "must not be written")
	waited := time.Since(t0)
	if err == nil || !isBusy(err) {
		t.Fatalf("a lock longer than the window: %v", err)
	}
	if waited > 6500*time.Millisecond {
		t.Fatalf("waited %v; the window is not bounded", waited)
	}
	if cerr := <-done; cerr != nil {
		t.Fatal(cerr)
	}
	got, _ := st.GetNote(sid, n.ID)
	if got.Revision != 1 || got.Body != "base" {
		t.Fatalf("a failed change was written: %+v", got)
	}
	t1 := time.Now()
	if _, err := st.UpdateNote(sid, n.ID, 7, "x", "y"); !errors.Is(err, ErrNoteConflict) || time.Since(t1) > time.Second {
		t.Fatalf("a conflict: %v after %v", err, time.Since(t1))
	}
}

// A wrong key still fails at once with the decryption error; the lock retry
// is not involved in opening. (Encrypted build only: the plain build has no
// key.)
func TestWrongKeyFailsWhileAnotherWriterHoldsTheLock(t *testing.T) {
	if !Encrypted() {
		t.Skip("the plain development build has no key")
	}
	st := openTemp(t)
	sid, _ := notesSession(t, st)
	path := filepath.Join(filepath.Dir(st.path), "t.db")
	done := holdWriteLock(t, path, sid, []byte("held\n"), 2*time.Second)
	t0 := time.Now()
	_, err := Open(path, []byte("not-the-key"))
	if err == nil || !strings.Contains(err.Error(), "could not decrypt") {
		t.Fatalf("wrong key: %v", err)
	}
	if d := time.Since(t0); d > 30*time.Second {
		t.Fatalf("wrong key took %v", d)
	}
	<-done
}
