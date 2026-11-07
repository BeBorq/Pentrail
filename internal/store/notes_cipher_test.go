//go:build sqlcipher

package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const notesKey = "synthetic-notes-cipher-key"

// A database written by 0.6.26 has no notes table. This one is built through
// the store and then has the notes table and index dropped through a raw
// SQLCipher connection, leaving exactly the 0.6.26 schema. Opening it with
// this build adds the table (an additive migration) and leaves every evidence
// row, the schema of the evidence tables and user_version unchanged.
// (A database written by the real 0.6.26 binary is covered by the external
// run documented in the 04BJ report.)
func TestNotesMigrateA0626DatabaseWithoutChangingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old26.db")
	st, err := Open(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := notesSession(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := openDB(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP INDEX idx_notes_session; DROP TABLE notes;`); err != nil {
		t.Fatal(err)
	}
	var n int
	raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE '%notes%'`).Scan(&n)
	if n != 0 {
		t.Fatal("precondition: notes schema still present")
	}
	var oldSchema string
	raw.QueryRow(`SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name)`).Scan(&oldSchema)
	var oldVersion int
	raw.QueryRow(`PRAGMA user_version`).Scan(&oldVersion)
	before := evidenceDigest(t, raw)
	raw.Close()

	st, err = Open(path, []byte(notesKey))
	if err != nil {
		t.Fatalf("opening a 0.6.26 database: %v", err)
	}
	if got := evidenceDigest(t, st.DB()); got != before {
		t.Fatal("opening with notes support changed evidence")
	}
	var newSchema string
	st.DB().QueryRow(`SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE '%notes%' ORDER BY name)`).Scan(&newSchema)
	if newSchema != oldSchema {
		t.Fatalf("evidence schema changed:\nold %s\nnew %s", oldSchema, newSchema)
	}
	var v int
	st.DB().QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != oldVersion {
		t.Fatalf("user_version %d -> %d", oldVersion, v)
	}
	note, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0)}, "after migration", "ok")
	if err != nil {
		t.Fatal(err)
	}
	if got := evidenceDigest(t, st.DB()); got != before {
		t.Fatal("a note changed evidence")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got, err := st.GetNote(sid, note.ID); err != nil || got.Title != "after migration" {
		t.Fatalf("note after reopen: %+v %v", got, err)
	}
	requireNotesIntegrity(t, st.DB())
}

// Notes written by ANOTHER process (the viewer) while this process records:
// capture never fails, offsets stay contiguous, and no recorder write waits
// anywhere near the busy timeout.
func TestNotesWrittenByAnotherProcessWhileRecording(t *testing.T) {
	if os.Getenv("PENTRAIL_NOTES_HELPER") != "" {
		return
	}
	path := filepath.Join(t.TempDir(), "rec.db")
	st, err := Open(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := notesSession(t, st)
	var off int64
	if err := st.DB().QueryRow(`SELECT COALESCE(MAX(byte_offset+length(data)),0) FROM raw_chunks WHERE session_id=?`, sid).Scan(&off); err != nil {
		t.Fatal(err)
	}
	start := off
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var maxWait time.Duration
	var lines int
	var werr error
	wg.Add(1)
	go func() { // the recorder
		defer wg.Done()
		seq := int64(1000)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			line := []byte(fmt.Sprintf("rec-line-%05d password=Synthetic%05d\n", i, i))
			t0 := time.Now()
			if e := st.WriteRaw(sid, seq, off, line); e != nil {
				werr = e
				return
			}
			if d := time.Since(t0); d > maxWait {
				maxWait = d
			}
			seq++
			off += int64(len(line))
			lines++
			time.Sleep(2 * time.Millisecond)
		}
	}()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperNotesWriter$", "-test.v")
	cmd.Env = append(os.Environ(), "PENTRAIL_NOTES_HELPER="+path, "PENTRAIL_NOTES_SESSION="+strconv.FormatInt(sid, 10))
	out, herr := cmd.CombinedOutput()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if herr != nil || !strings.Contains(string(out), "NOTES-HELPER-DONE 60") {
		t.Fatalf("notes process: %v\n%s", herr, out)
	}
	if werr != nil {
		t.Fatalf("capture failed while notes were written: %v", werr)
	}
	if e := st.WriteError(); e != nil {
		t.Fatalf("sticky write error: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := st.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	data, missing, err := st.ReadRange(sid, start, off)
	if err != nil || missing != 0 || int64(len(data)) != off-start {
		t.Fatalf("recorded data damaged: %d/%d missing=%d err=%v", len(data), off-start, missing, err)
	}
	for i := 0; i < lines; i++ {
		if !strings.Contains(string(data), fmt.Sprintf("rec-line-%05d ", i)) {
			t.Fatalf("line %d missing", i)
		}
	}
	notes, err := st.ListNotes(sid)
	if err != nil || len(notes) != 20 {
		t.Fatalf("notes: %d %v", len(notes), err)
	}
	t.Logf("recorded %d lines (%d B) while another process wrote 60 note changes; longest recorder write %v", lines, off-start, maxWait)
	if maxWait > 2*time.Second {
		t.Fatalf("a recorder write waited %v", maxWait)
	}
	requireNotesIntegrity(t, st.DB())
}

func TestHelperNotesWriter(t *testing.T) {
	path := os.Getenv("PENTRAIL_NOTES_HELPER")
	if path == "" {
		t.Skip("helper process only")
	}
	sid, _ := strconv.ParseInt(os.Getenv("PENTRAIL_NOTES_SESSION"), 10, 64)
	st, err := Open(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	changes := 0
	for i := 0; i < 20; i++ {
		n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorCommand, CmdIndex: i64(0)}, fmt.Sprintf("note %d", i), "token=SyntheticSecret"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		n, err = st.UpdateNote(sid, n.ID, n.Revision, n.Title, n.Body+"\nmore")
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if _, err = st.SetNoteArchived(sid, n.ID, n.Revision, true); err != nil {
				t.Fatal(err)
			}
		} else if _, err = st.UpdateNote(sid, n.ID, n.Revision, n.Title, n.Body+"!"); err != nil {
			t.Fatal(err)
		}
		changes += 3
		time.Sleep(10 * time.Millisecond)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("NOTES-HELPER-DONE %d\n", changes)
}
