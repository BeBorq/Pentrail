package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReview040PausedFlushMustNotPersistDraft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	st, e := Open(path, []byte("synthetic-review-key"))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := st.StartSession("test", "test", "test")
	st.WriteRaw(id, 0, 0, []byte("PUBLIC\n"))
	st.PauseCapture(id)
	st.ObservePaused(id, []byte("PRIVATE_DRAFT_DURING_OFF"))
	st.MaskPendingRaw(id)
	if e = st.FinishSession(id); e != nil {
		t.Fatal(e)
	}
	st, e = Open(path, []byte("synthetic-review-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	raw, _, e := st.ReadRange(id, 0, 1000)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("PRIVATE_DRAFT_DURING_OFF")) {
		t.Fatalf("paused draft was persisted: %q", raw)
	}
}
func TestReview040ParserMustRequireFIN(t *testing.T) {
	st := openTemp(t)
	path := filepath.Join(t.TempDir(), "scan.json")
	os.WriteFile(path, []byte(`{"results":[{"url":"https://unfinished.example/hit","status":200}]}`), 0600)
	st.DB().Exec("INSERT INTO sessions(id,started_at) VALUES(1,1)")
	st.DB().Exec("INSERT INTO commands(session_id,cmd_index,command,complete) VALUES(1,0,'ffuf',1)")
	st.DB().Exec("INSERT INTO command_artifacts(session_id,cmd_index,tool,path,finalized,ingested) VALUES(1,0,'ffuf',?,0,0)", path)
	n, files, e := st.ParseArtifacts(1)
	if e != nil {
		t.Fatal(e)
	}
	if files != 0 || n != 0 {
		t.Fatalf("unfinalized artifact parsed: files=%d entities=%d", files, n)
	}
}
func TestReview040ReparseMustRemoveObsoleteFindings(t *testing.T) {
	st := openTemp(t)
	seedArtifact(t, st, 0, "ffuf", "ffuf", []byte(`{"results":[{"url":"https://example.test/old","status":200}]}`))
	if _, _, e := st.ParseArtifacts(1); e != nil {
		t.Fatal(e)
	}
	data := []byte(`{"results":[{"url":"https://example.test/new","status":200}]}`)
	sum := sha256.Sum256(data)
	st.DB().Exec("UPDATE command_artifacts SET content=?,sha256=?,length=?", data, hex.EncodeToString(sum[:]), len(data))
	if _, _, e := st.ParseArtifacts(1); e != nil {
		t.Fatal(e)
	}
	if n := countEntities(t, st, "value=?", "https://example.test/old"); n != 0 {
		t.Fatalf("obsolete endpoint retained after successful reparse: %d", n)
	}
}

func TestReview050EmptySuccessfulArtifactReplacesOnlyItsOwnFindings(t *testing.T) {
	st := openTemp(t)
	seedArtifact(t, st, 0, "ffuf", "ffuf", []byte(`{"results":[{"url":"https://a.example.test/old"}]}`))
	seedArtifact(t, st, 1, "ffuf", "ffuf", []byte(`{"results":[{"url":"https://b.example.test/keep"}]}`))
	if _, _, e := st.ParseArtifacts(1); e != nil {
		t.Fatal(e)
	}
	data := []byte(`{"results":[]}`)
	sum := sha256.Sum256(data)
	if _, e := st.DB().Exec("UPDATE command_artifacts SET content=?,sha256=?,length=? WHERE cmd_index=0", data, hex.EncodeToString(sum[:]), len(data)); e != nil {
		t.Fatal(e)
	}
	if _, _, e := st.ParseArtifacts(1); e != nil {
		t.Fatal(e)
	}
	if countEntities(t, st, "value=?", "https://a.example.test/old") != 0 || countEntities(t, st, "value=?", "https://b.example.test/keep") != 1 {
		t.Fatal("empty result retained old findings or damaged unrelated artifact")
	}
}
