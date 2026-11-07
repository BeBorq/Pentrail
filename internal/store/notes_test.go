package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Operator notes (04BJ): storage, validation, masking, revisions and
// archive/restore. Notes are annotations, never evidence: every test also
// checks that the evidence tables are byte-for-byte unchanged.

// notesSession builds a synthetic session with raw output, two commands, a
// host and a port, and returns the session ID and a graph node ID.
func notesSession(t *testing.T, st *Store) (int64, string) {
	t.Helper()
	id, err := st.StartSession("bash", "synthetic-host", "test")
	if err != nil {
		t.Fatal(err)
	}
	out := []byte("$ nmap -sV 10.0.0.5\n22/tcp open ssh OpenSSH 9.6\n")
	if err := st.WriteRaw(id, 0, 0, out); err != nil {
		t.Fatal(err)
	}
	st.WriteCommand(Command{SessionID: id, Index: 0, Command: "nmap -sV 10.0.0.5", OutStartOff: 0, OutEndOff: int64(len(out)), Complete: true})
	st.WriteCommand(Command{SessionID: id, Index: 1, Command: "echo done", OutStartOff: int64(len(out)), OutEndOff: int64(len(out)), Complete: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := st.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	var cid int64
	if err := st.DB().QueryRow(`SELECT id FROM commands WHERE session_id=? AND cmd_index=0`, id).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	for _, e := range [][3]string{{"host", "10.0.0.5", ""}, {"port", "10.0.0.5:22/tcp", `{"service":"ssh"}`}} {
		if _, err := st.DB().Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,tool,extractor,details,obs_key)
			VALUES(?,?,?,?,?,?,?,?,?)`, id, e[0], e[1], "high", cid, "nmap", "parser:nmap", nullIfEmpty(e[2]), "parser:nmap\x1f"+e[0]+"\x1f"+e[1]); err != nil {
			t.Fatal(err)
		}
	}
	g, err := st.BuildGraph(id)
	if err != nil || len(g.Nodes) == 0 {
		t.Fatalf("graph: %v %d", err, len(g.Nodes))
	}
	return id, g.Nodes[0].ID
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// evidenceDigest hashes every table except notes, row by row.
func evidenceDigest(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'notes' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	h := sha256.New()
	for _, tb := range tables {
		r, err := db.Query(`SELECT * FROM "` + tb + `" ORDER BY 1`)
		if err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
		cols, _ := r.Columns()
		fmt.Fprintf(h, "table %s %v\n", tb, cols)
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(h, "%q\n", fmt.Sprint(vals...))
		}
		r.Close()
	}
	return hex.EncodeToString(h.Sum(nil))
}

func i64(v int64) *int64 { return &v }

// requireNotesIntegrity runs SQLite's integrity_check and foreign_key_check.
// It is defined here, in a file built on every platform: the store package's
// integrityOK helper lives in wal_lock_linux_test.go and exists only on Linux.
func requireNotesIntegrity(t *testing.T, db *sql.DB) {
	t.Helper()
	var v string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&v); err != nil || v != "ok" {
		t.Fatalf("integrity_check: %q %v", v, err)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reports violations")
	}
}

func TestNotesCreateReadUpdateArchiveWithoutTouchingEvidence(t *testing.T) {
	st := openTemp(t)
	sid, node := notesSession(t, st)
	other, _ := st.StartSession("bash", "h", "v")
	before := evidenceDigest(t, st.DB())

	title := "Zażółć gęślą jaźń — 東京 🛰️"
	body := "line 1\n<script>alert('x')</script>\n**not bold** `code` &amp;\r\n\ttabbed"
	n, err := st.CreateNote(sid, NoteAnchor{}, title, body)
	if err != nil {
		t.Fatal(err)
	}
	if n.Title != title || n.Body != body || n.Revision != 1 || n.Archived || n.AnchorLabel != "session" || len(n.ID) != 32 || n.MaskedBytes != 0 {
		t.Fatalf("created note: %+v", n)
	}
	c, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0)}, "cmd", "")
	if err != nil || c.CmdIndex == nil || *c.CmdIndex != 0 || !strings.HasPrefix(c.AnchorLabel, "command #0: nmap -sV 10.0.0.5") {
		t.Fatalf("command note: %+v %v", c, err)
	}
	g, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorNode, NodeID: node}, "node", "")
	if err != nil || g.NodeID != node || !strings.HasPrefix(g.AnchorLabel, "graph element (") {
		t.Fatalf("node note: %+v %v", g, err)
	}

	u, err := st.UpdateNote(sid, n.ID, 1, "t2", "b2")
	if err != nil || u.Revision != 2 || u.Title != "t2" || u.Body != "b2" || u.CreatedMs != n.CreatedMs {
		t.Fatalf("update: %+v %v", u, err)
	}
	// stale revision: refused, the current note is returned, nothing changes
	cur, err := st.UpdateNote(sid, n.ID, 1, "lost", "lost")
	if !errors.Is(err, ErrNoteConflict) || cur.Revision != 2 || cur.Body != "b2" {
		t.Fatalf("stale update: %+v %v", cur, err)
	}
	a, err := st.SetNoteArchived(sid, n.ID, 2, true)
	if err != nil || !a.Archived || a.Revision != 3 || a.Body != "b2" {
		t.Fatalf("archive: %+v %v", a, err)
	}
	if _, err := st.UpdateNote(sid, n.ID, 3, "x", "x"); !errors.Is(err, ErrNoteConflict) {
		t.Fatalf("an archived note was edited: %v", err)
	}
	if _, err := st.SetNoteArchived(sid, n.ID, 3, true); !errors.Is(err, ErrNoteConflict) {
		t.Fatalf("archiving twice: %v", err)
	}
	if _, err := st.SetNoteArchived(sid, n.ID, 2, false); !errors.Is(err, ErrNoteConflict) {
		t.Fatalf("restore at a stale revision: %v", err)
	}
	r, err := st.SetNoteArchived(sid, n.ID, 3, false)
	if err != nil || r.Archived || r.Revision != 4 || r.Body != "b2" {
		t.Fatalf("restore: %+v %v", r, err)
	}
	list, err := st.ListNotes(sid)
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	// session ownership: another session (or none) never sees or changes it
	if _, err := st.GetNote(other, n.ID); !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("read through another session: %v", err)
	}
	if _, err := st.UpdateNote(other, n.ID, 4, "x", "x"); !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("update through another session: %v", err)
	}
	if _, err := st.SetNoteArchived(other, n.ID, 4, true); !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("archive through another session: %v", err)
	}
	if l, _ := st.ListNotes(other); len(l) != 0 {
		t.Fatalf("other session lists %d notes", len(l))
	}
	if after := evidenceDigest(t, st.DB()); after != before {
		t.Fatal("writing notes changed evidence tables")
	}
}

func TestNotesMaskRecognizedSecretsBeforeStoring(t *testing.T) {
	st := openTemp(t)
	sid, _ := notesSession(t, st)
	secret := "hunter2-Synthetic-Pw"
	n, err := st.CreateNote(sid, NoteAnchor{}, "password="+secret, "login with\npassword="+secret+"\nthen ok")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(n.Title+n.Body, secret) || n.MaskedBytes < int64(2*len(secret)) {
		t.Fatalf("not masked: %+v", n)
	}
	if len(n.Body) != len("login with\npassword="+secret+"\nthen ok") {
		t.Fatalf("masking changed the length: %q", n.Body)
	}
	var raw string
	st.DB().QueryRow(`SELECT title||body FROM notes WHERE id=?`, n.ID).Scan(&raw)
	if strings.Contains(raw, secret) {
		t.Fatal("the secret is stored")
	}
	u, err := st.UpdateNote(sid, n.ID, 1, "clean", "nothing secret")
	if err != nil || u.MaskedBytes != 0 {
		t.Fatalf("masked count of the last save: %+v %v", u, err)
	}
	u, _ = st.UpdateNote(sid, n.ID, 2, "clean", "token="+secret)
	if strings.Contains(u.Body, secret) || u.MaskedBytes == 0 {
		t.Fatalf("update not masked: %+v", u)
	}
}

func TestNotesRejectInvalidInput(t *testing.T) {
	st := openTemp(t)
	sid, node := notesSession(t, st)
	other, _ := st.StartSession("bash", "h", "v")
	bad := []struct {
		name   string
		sid    int64
		a      NoteAnchor
		t, b   string
		reason string
	}{
		{"missing session", 9999, NoteAnchor{}, "t", "b", "does not exist"},
		{"command of another session", other, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0)}, "t", "b", "not in session"},
		{"missing command", sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(7)}, "t", "b", "not in session"},
		{"negative command", sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(-1)}, "t", "b", "command number"},
		{"command without number", sid, NoteAnchor{Kind: AnchorCommand}, "t", "b", "command number"},
		{"command with node", sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0), NodeID: node}, "t", "b", "command number"},
		{"node of another session", other, NoteAnchor{Kind: AnchorNode, NodeID: node}, "t", "b", "not in the graph"},
		{"unknown node", sid, NoteAnchor{Kind: AnchorNode, NodeID: node + "x"}, "t", "b", "not in the graph"},
		{"node too long", sid, NoteAnchor{Kind: AnchorNode, NodeID: strings.Repeat("a", NoteNodeIDMax+1)}, "t", "b", "exact graph element"},
		{"session with extra", sid, NoteAnchor{CmdIndex: i64(0)}, "t", "b", "no command or element"},
		{"unknown kind", sid, NoteAnchor{Kind: "file"}, "t", "b", "unknown anchor"},
		{"title too long", sid, NoteAnchor{}, strings.Repeat("é", NoteTitleMax/2+1), "b", "title is longer"},
		{"body too long", sid, NoteAnchor{}, "t", strings.Repeat("x", NoteBodyMax+1), "text is longer"},
		{"invalid UTF-8", sid, NoteAnchor{}, "t", "a\xffb", "UTF-8"},
		{"NUL", sid, NoteAnchor{}, "t\x00", "b", "NUL"},
	}
	for _, c := range bad {
		_, err := st.CreateNote(c.sid, c.a, c.t, c.b)
		if !errors.Is(err, ErrNoteInvalid) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// exactly at the limits is accepted
	n, err := st.CreateNote(sid, NoteAnchor{}, strings.Repeat("t", NoteTitleMax), strings.Repeat("b", NoteBodyMax))
	if err != nil {
		t.Fatalf("at the limits: %v", err)
	}
	if _, err := st.UpdateNote(sid, n.ID, 1, "t", strings.Repeat("b", NoteBodyMax+1)); !errors.Is(err, ErrNoteInvalid) {
		t.Fatalf("update over the limit: %v", err)
	}
	if _, err := st.UpdateNote(sid, strings.Repeat("0", 32), 1, "t", "b"); !errors.Is(err, ErrNoteNotFound) {
		t.Fatalf("missing note: %v", err)
	}
	var count int
	st.DB().QueryRow(`SELECT count(*) FROM notes`).Scan(&count)
	if count != 1 {
		t.Fatalf("rejected notes were stored: %d", count)
	}
}

// An anchor that disappears later (here: its entity is removed, so the graph
// element is gone) does not destroy the note; the snapshot label stays.
func TestNoteSurvivesAMissingAnchor(t *testing.T) {
	st := openTemp(t)
	sid, node := notesSession(t, st)
	n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorNode, NodeID: node}, "about this element", "text")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`DELETE FROM entities WHERE session_id=?`, sid); err != nil {
		t.Fatal(err)
	}
	g, _ := st.BuildGraph(sid)
	if len(g.Nodes) != 0 {
		t.Fatal("precondition: the element is still in the graph")
	}
	got, err := st.GetNote(sid, n.ID)
	if err != nil || got.NodeID != node || got.AnchorLabel != n.AnchorLabel || got.Body != "text" {
		t.Fatalf("note after its anchor disappeared: %+v %v", got, err)
	}
	if _, err := st.UpdateNote(sid, n.ID, 1, "still editable", "text"); err != nil {
		t.Fatalf("a note with a missing anchor must stay editable: %v", err)
	}
}

func TestNotesSurviveReopenAndEncryptedBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.db")
	key := []byte("synthetic-notes-key")
	st, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := notesSession(t, st)
	n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(1)}, "kept", "Unicode ✓ <b>x</b>")
	if err != nil {
		t.Fatal(err)
	}
	n, _ = st.SetNoteArchived(sid, n.ID, 1, true)
	if err := st.Close(); err != nil { // Close finalizes the session (evidence), so compare from here on
		t.Fatal(err)
	}
	reopen := func(p string) *Store {
		s, err := Open(p, key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	st = reopen(path)
	digest := evidenceDigest(t, st.DB())
	if got, err := st.GetNote(sid, n.ID); err != nil || !reflect.DeepEqual(got, n) {
		t.Fatalf("after reopen: %+v %v (want %+v)", got, err, n)
	}
	st.Close()
	st = reopen(path)
	if evidenceDigest(t, st.DB()) != digest {
		t.Fatal("evidence changed by a reopen with notes")
	}
	st.Close()
	dest := filepath.Join(dir, "backup.db")
	if _, err := BackupFile(path, dest, key); err != nil {
		if strings.Contains(err.Error(), "SQLCipher build") {
			t.Skipf("plain build: %v", err)
		}
		t.Fatal(err)
	}
	b := reopen(dest)
	defer b.Close()
	if got, err := b.GetNote(sid, n.ID); err != nil || !reflect.DeepEqual(got, n) {
		t.Fatalf("backup lacks the note: %+v %v", got, err)
	}
	if evidenceDigest(t, b.DB()) != digest {
		t.Fatal("backup evidence differs")
	}
}

// Notes are never deleted through the store API: there is no delete method.
func TestNotesHaveNoDeleteAPI(t *testing.T) {
	var s any = (*Store)(nil)
	if _, ok := s.(interface {
		DeleteNote(int64, string) error
	}); ok {
		t.Fatal("a DeleteNote method exists")
	}
}

// A note write and its reply are one transaction. Deterministic: inside the
// write (test hook, after the change, before the read-back) a SECOND
// connection — another viewer — starts its own change of the same note and is
// given 300 ms to finish. With the transaction it cannot commit before this
// write's reply is read, so each reply shows exactly its own accepted
// revision and text. (With a separate read after the write, as in 04BJ, the
// other writer commits first and this reply shows the other's text.)
func TestNoteWriteReplyIsExactlyTheCommittedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "atomic.db")
	key := []byte("synthetic-atomic-key")
	st, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := notesSession(t, st)
	otherDB, err := openDB(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	other := &Store{db: otherDB} // another process's viewer: its own connection
	type result struct {
		n   Note
		err error
	}
	// race runs mine(); while it is inside its transaction, theirs() starts.
	race := func(mine func() (Note, error), theirs func() (Note, error)) (Note, error, result) {
		done := make(chan result, 1)
		started := false
		testHookNoteWritten = func(string) {
			if started {
				return
			}
			started = true
			go func() { n, err := theirs(); done <- result{n, err} }()
			select {
			case r := <-done: // finished inside our write: the reply below would be theirs
				done <- r
			case <-time.After(300 * time.Millisecond):
			}
		}
		defer func() { testHookNoteWritten = nil }()
		n, err := mine()
		return n, err, <-done
	}

	n, err := st.CreateNote(sid, NoteAnchor{}, "base", "v1")
	if err != nil {
		t.Fatal(err)
	}
	// UpdateNote: mine 1->2, theirs 2->3
	mine, err, theirs := race(
		func() (Note, error) { return st.UpdateNote(sid, n.ID, 1, "mine", "my text") },
		func() (Note, error) { return other.UpdateNote(sid, n.ID, 2, "theirs", "their text") })
	if err != nil || mine.Revision != 2 || mine.Title != "mine" || mine.Body != "my text" {
		t.Fatalf("my reply is not my committed write: %+v %v", mine, err)
	}
	if theirs.err != nil || theirs.n.Revision != 3 || theirs.n.Body != "their text" {
		t.Fatalf("their reply: %+v %v", theirs.n, theirs.err)
	}
	// SetNoteArchived: mine archives 3->4, theirs restores 4->5
	mine, err, theirs = race(
		func() (Note, error) { return st.SetNoteArchived(sid, n.ID, 3, true) },
		func() (Note, error) { return other.SetNoteArchived(sid, n.ID, 4, false) })
	if err != nil || mine.Revision != 4 || !mine.Archived || mine.Body != "their text" {
		t.Fatalf("my archive reply: %+v %v", mine, err)
	}
	if theirs.err != nil || theirs.n.Revision != 5 || theirs.n.Archived {
		t.Fatalf("their restore reply: %+v %v", theirs.n, theirs.err)
	}
	// CreateNote: theirs edits the new note (revision 1) while mine is inside its write
	var created string
	mine, err, theirs = race(
		func() (Note, error) { return st.CreateNote(sid, NoteAnchor{}, "new", "created") },
		func() (Note, error) {
			for created == "" { // the ID is known once mine committed; poll the table
				var id string
				if otherDB.QueryRow(`SELECT id FROM notes WHERE title='new'`).Scan(&id) == nil {
					created = id
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			return other.UpdateNote(sid, created, 1, "new", "edited by them")
		})
	if err != nil || mine.Revision != 1 || mine.Body != "created" {
		t.Fatalf("my create reply: %+v %v", mine, err)
	}
	if theirs.err != nil || theirs.n.Revision != 2 || theirs.n.ID != mine.ID {
		t.Fatalf("their edit of the new note: %+v %v", theirs.n, theirs.err)
	}
	// A conflict reply is the current row at the moment of the refusal.
	cur, err := st.UpdateNote(sid, n.ID, 1, "stale", "stale")
	if !errors.Is(err, ErrNoteConflict) || cur.Revision != 5 {
		t.Fatalf("conflict: %+v %v", cur, err)
	}
	final, _ := st.GetNote(sid, n.ID)
	if final.Revision != 5 || final.Body != "their text" || final.Archived {
		t.Fatalf("final row: %+v", final)
	}
	requireNotesIntegrity(t, st.DB())
}
