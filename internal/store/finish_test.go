package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFinishSessionDrainsFinalizedArtifactBeforeIngest(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "session.db")
	path := filepath.Join(dir, "scan.xml")
	key := []byte("finish-test-key")
	st, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.StartSession("sh", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("complete artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	st.WriteArtifact(id, 0, "nmap", path)
	st.MarkArtifactFinalized(id, path)
	if err := st.FinishSession(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("plaintext artifact remains: %v", err)
	}
	reopened, err := Open(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var b []byte
	if err := reopened.DB().QueryRow("SELECT content FROM command_artifacts WHERE session_id=? AND ingested=1", id).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "complete artifact" {
		t.Fatal(string(b))
	}
}
