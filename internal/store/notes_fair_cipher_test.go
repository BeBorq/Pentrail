//go:build sqlcipher

package store

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Note changes made back to back by another process must not keep a capture
// write waiting through all of them. SQLite has no fair lock queue: the
// capture write polls from its busy handler, and note changes that took the
// lock again right after each commit starved it for as long as they continued
// (windows-2025 CI: 2.26 s; Linux with an emulated 20-40 ms flush: 1.0-2.8 s,
// covering every note change of the other process). Here the other process
// holds the lock 50 ms per change (inside the change, before its commit) and
// starts the next change at once. Criterion (no wall-clock limit): while one
// capture write waits, the other process commits at most 2 note changes.
//
// Negative control (manual): PENTRAIL_NOTES_GAP_CONTROL=1 runs the other
// process with noteWriteGap=0, the old behaviour; the test then fails.
func TestCaptureWriteIsNotStarvedByBackToBackNoteChanges(t *testing.T) {
	if os.Getenv("PENTRAIL_NOTES_HELPER") != "" {
		return
	}
	path := filepath.Join(t.TempDir(), "fair.db")
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
	type span struct{ a, b int64 }
	var writes []span
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { // the recorder
		seq := int64(1000)
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			line := []byte(fmt.Sprintf("fair-line-%05d password=Synthetic%05d\n", i, i))
			a := time.Now().UnixNano()
			if e := st.WriteRaw(sid, seq, off, line); e != nil {
				done <- e
				return
			}
			writes = append(writes, span{a, time.Now().UnixNano()})
			seq++
			off += int64(len(line))
			time.Sleep(2 * time.Millisecond)
		}
	}()
	commitsFile := filepath.Join(t.TempDir(), "commits.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperBackToBackNotes$", "-test.v")
	cmd.Env = append(os.Environ(), "PENTRAIL_NOTES_HELPER="+path, "PENTRAIL_NOTES_SESSION="+strconv.FormatInt(sid, 10), "PENTRAIL_NOTES_COMMITS="+commitsFile)
	out, herr := cmd.CombinedOutput()
	time.Sleep(100 * time.Millisecond)
	close(stop)
	if e := <-done; e != nil {
		t.Fatalf("capture failed while notes were written: %v", e)
	}
	if herr != nil || !strings.Contains(string(out), "BACK-TO-BACK-DONE 12") {
		t.Fatalf("notes process: %v\n%s", herr, out)
	}
	var commits []int64
	if b, e := os.ReadFile(commitsFile); e != nil || json.Unmarshal(b, &commits) != nil || len(commits) != 12 {
		t.Fatalf("note commit times: %v %d", e, len(commits))
	}
	worst, worstWait := 0, int64(0)
	for _, w := range writes {
		n := 0
		for _, c := range commits {
			if c > w.a && c < w.b {
				n++
			}
		}
		if n > worst || (n == worst && w.b-w.a > worstWait) {
			worst, worstWait = n, w.b-w.a
		}
	}
	t.Logf("%d capture writes; at most %d note commits during one capture write (it waited %v)", len(writes), worst, time.Duration(worstWait))
	if worst > 2 {
		t.Fatalf("one capture write waited through %d of 12 back-to-back note changes (%v)", worst, time.Duration(worstWait))
	}
	if e := st.WriteError(); e != nil {
		t.Fatalf("sticky write error: %v", e)
	}
	data, missing, err := st.ReadRange(sid, start, off)
	if err != nil || missing != 0 || int64(len(data)) != off-start {
		t.Fatalf("recorded data damaged: %d/%d missing=%d err=%v", len(data), off-start, missing, err)
	}
	notes, err := st.ListNotes(sid)
	if err != nil || len(notes) != 6 {
		t.Fatalf("notes: %d %v", len(notes), err)
	}
	for _, n := range notes {
		if n.Revision != 2 || strings.Contains(n.Body, "SyntheticFair") {
			t.Fatalf("note %+v", n)
		}
	}
	requireNotesIntegrity(t, st.DB())
}

// The other process: 6 notes, each created and changed once, 12 changes back
// to back; each change holds the write lock for 50 ms before its commit.
func TestHelperBackToBackNotes(t *testing.T) {
	path, commitsFile := os.Getenv("PENTRAIL_NOTES_HELPER"), os.Getenv("PENTRAIL_NOTES_COMMITS")
	if path == "" || commitsFile == "" {
		t.Skip("helper process only")
	}
	if os.Getenv("PENTRAIL_NOTES_GAP_CONTROL") != "" {
		noteWriteGap = 0 // negative control: the old back-to-back behaviour
	}
	sid, _ := strconv.ParseInt(os.Getenv("PENTRAIL_NOTES_SESSION"), 10, 64)
	st, err := Open(path, []byte(notesKey))
	if err != nil {
		t.Fatal(err)
	}
	testHookNoteWritten = func(string) { time.Sleep(50 * time.Millisecond) }
	var commits []int64
	for i := 0; i < 6; i++ {
		n, err := st.CreateNote(sid, NoteAnchor{Kind: AnchorSession}, fmt.Sprintf("fair %d", i), "token=SyntheticFair"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		commits = append(commits, time.Now().UnixNano())
		if _, err = st.UpdateNote(sid, n.ID, n.Revision, n.Title, n.Body+" changed"); err != nil {
			t.Fatal(err)
		}
		commits = append(commits, time.Now().UnixNano())
	}
	testHookNoteWritten = nil
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(commits)
	if err := os.WriteFile(commitsFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("BACK-TO-BACK-DONE %d\n", len(commits))
}
