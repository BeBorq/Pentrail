package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLargeArtifactRetainsAllJSONResults(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ffuf.json")
	var rows []map[string]interface{}
	for i := 0; i < 2500; i++ {
		rows = append(rows, map[string]interface{}{"url": fmt.Sprintf("https://large.example.test/result/%04d", i), "status": 200})
	}
	original, _ := json.Marshal(map[string]interface{}{"results": rows, "config": map[string]interface{}{"token": "LargeArtifactSecret"}})
	if len(original) < 65536 {
		t.Fatal("fixture too small")
	}
	os.WriteFile(path, original, 0600)
	st.DB().Exec("INSERT INTO sessions(id,started_at) VALUES(1,1)")
	st.DB().Exec("INSERT INTO commands(session_id,cmd_index,command,complete) VALUES(1,0,'ffuf',1)")
	st.DB().Exec("INSERT INTO command_artifacts(session_id,cmd_index,tool,path,finalized) VALUES(1,0,'ffuf',?,1)", path)
	if n, e := st.IngestArtifacts(1); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	var content []byte
	st.DB().QueryRow("SELECT content FROM command_artifacts WHERE session_id=1").Scan(&content)
	if !json.Valid(content) || bytes.Contains(content, []byte("LargeArtifactSecret")) {
		t.Fatal("structure or privacy lost")
	}
	if n, files, e := st.ParseArtifacts(1); e != nil || files != 1 || n != 2500 {
		t.Fatal("large artifact results lost", n, files, e)
	}
	t.Logf("structured_file_bytes=%d all_results=2500/2500 secret_masked=true", len(content))
}
func TestMalformedArtifactIsRetainedOnDisk(t *testing.T) {
	st := openTemp(t)
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("{unfinished"), 0600)
	st.DB().Exec("INSERT INTO sessions(id,started_at) VALUES(1,1)")
	st.DB().Exec("INSERT INTO command_artifacts(session_id,cmd_index,tool,path,finalized) VALUES(1,0,'ffuf',?,1)", path)
	// Retained for manual handling — but it must not fail the whole batch:
	// that error made serve/open/report/export/parse unusable for good.
	if n, e := st.IngestArtifacts(1); e != nil || n != 0 {
		t.Fatal("malformed artifact must be skipped, not fail the batch:", n, e)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("invalid original removed", e)
	}
	var ingested int
	st.DB().QueryRow("SELECT ingested FROM command_artifacts WHERE path=?", path).Scan(&ingested)
	if ingested != 0 {
		t.Fatal("invalid artifact accepted")
	}
}
