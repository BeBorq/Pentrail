package store

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

// P1.2: if raw bytes cannot be persisted, the failure must surface — Close()
// returns an error so the caller can exit non-zero instead of pretending the
// capture is complete.
func TestRawWriteFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "t.db"), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	st.DB().Exec(`INSERT INTO sessions(id, started_at) VALUES(1,1)`)
	// Make raw persistence impossible.
	if _, err := st.DB().Exec(`DROP TABLE raw_chunks`); err != nil {
		t.Fatal(err)
	}
	st.WriteRaw(1, 0, 0, []byte("evidence-bytes"))
	time.Sleep(120 * time.Millisecond) // let the writer try and fail at least once

	if err := st.Close(); err == nil {
		t.Fatal("expected Close() to report incomplete evidence, got nil")
	}
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "t.db"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seedArtifact inserts a session (id 1), a command, and an ingested artifact
// whose content is given inline.
func seedArtifact(t *testing.T, st *Store, cmdIndex int64, tool, command string, content []byte) {
	t.Helper()
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1, 1)`)
	if _, err := db.Exec(`INSERT INTO commands(session_id, cmd_index, command, out_start_off, out_end_off, complete) VALUES(1,?,?,0,0,1)`, cmdIndex, command); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if _, err := db.Exec(`INSERT INTO command_artifacts(session_id, cmd_index, tool, path, sha256, length, content, ingested) VALUES(1,?,?,?,?,?,?,1)`,
		cmdIndex, tool, "/does/not/exist/"+tool, hex.EncodeToString(sum[:]), len(content), content); err != nil {
		t.Fatal(err)
	}
}

func countEntities(t *testing.T, st *Store, where string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM entities WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// P1.5: two Nuclei findings with the same name but different targets must not
// collapse into one row.
func TestNucleiFindingsNotCollapsed(t *testing.T) {
	st := openTemp(t)
	content := []byte(`{"template-id":"CVE-X","info":{"name":"Example RCE","severity":"critical"},"host":"a.test","matched-at":"http://a.test/x"}
{"template-id":"CVE-X","info":{"name":"Example RCE","severity":"critical"},"host":"b.test","matched-at":"http://b.test/x"}`)
	seedArtifact(t, st, 0, "nuclei", "nuclei -u a.test", content)

	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if got := countEntities(t, st, `type='finding'`); got != 2 {
		t.Fatalf("findings: got %d, want 2 (must not collapse by name)", got)
	}
}

// P1.4: a low-confidence regex entity must not block the high-confidence parser
// entity for the same value and command.
func TestRegexDoesNotBlockParser(t *testing.T) {
	st := openTemp(t)
	seedArtifact(t, st, 0, "nmap", "nmap h",
		[]byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>`))

	// simulate the regex pass having already written a low-confidence host
	_, err := st.DB().Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,tool,extractor,obs_key)
	    VALUES(1,'host','10.0.0.1','low',(SELECT id FROM commands WHERE session_id=1 AND cmd_index=0),'nmap','regex:host','regex` + "\x1f" + `host` + "\x1f" + `10.0.0.1` + "\x1f" + `0')`)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	if got := countEntities(t, st, `type='host' AND value='10.0.0.1' AND confidence='high'`); got != 1 {
		t.Fatalf("high-confidence host: got %d, want 1 (parser must not be blocked by regex)", got)
	}
	if got := countEntities(t, st, `type='host' AND value='10.0.0.1' AND confidence='low'`); got != 1 {
		t.Fatalf("low-confidence host: got %d, want 1 (regex observation should remain)", got)
	}
}

// P1.6: re-parsing when one artifact has become unreadable must not delete the
// entities produced by artifacts that still parse.
func TestReparseDoesNotWipeOnMissingArtifact(t *testing.T) {
	st := openTemp(t)
	seedArtifact(t, st, 0, "nmap", "nmap a",
		[]byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>`))
	seedArtifact(t, st, 1, "nmap", "nmap b",
		[]byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`))

	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	before := countEntities(t, st, `extractor LIKE 'parser:%'`)
	if before == 0 {
		t.Fatal("expected some parser entities after first parse")
	}

	// Make the SECOND artifact unreadable: not ingested, no content, bad path.
	if _, err := st.DB().Exec(`UPDATE command_artifacts SET ingested=0, content=NULL WHERE cmd_index=1`); err != nil {
		t.Fatal(err)
	}

	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	// Entities for the first artifact (10.0.0.1) must survive.
	if got := countEntities(t, st, `type='host' AND value='10.0.0.1'`); got != 1 {
		t.Fatalf("host 10.0.0.1 after reparse: got %d, want 1 (must not be wiped)", got)
	}
	// And the second artifact's prior entities (10.0.0.2) also survive, because
	// we only replace what we successfully re-read.
	if got := countEntities(t, st, `type='host' AND value='10.0.0.2'`); got != 1 {
		t.Fatalf("host 10.0.0.2 after reparse of missing artifact: got %d, want 1 (kept)", got)
	}
}
