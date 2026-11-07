package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadArtifactSafeguards(t *testing.T) {
	dir := t.TempDir()

	// regular, quiescent file within cap: accepted
	reg := filepath.Join(dir, "ok.xml")
	if err := os.WriteFile(reg, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, ok := readLimited(reg, 10, 0); !ok || string(data) != "hello" {
		t.Fatalf("regular file: ok=%v data=%q", ok, data)
	}

	// over the hard cap: rejected (read is bounded, not just a prior stat)
	big := filepath.Join(dir, "big.xml")
	if err := os.WriteFile(big, make([]byte, 20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readLimited(big, 10, 0); ok {
		t.Fatal("oversized file should be rejected by the hard cap")
	}

	// freshly written file with a quiescence window: rejected (may still be open)
	if _, ok := readLimited(reg, 1<<20, time.Hour); ok {
		t.Fatal("a file within the quiescence window must be skipped")
	}

	// symlink to a target: rejected (O_NOFOLLOW)
	link := filepath.Join(dir, "link.xml")
	if err := os.Symlink(reg, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, ok := readLimited(link, 1<<20, 0); ok {
		t.Fatal("symlink must not be followed")
	}
}

// An artifact is ingested (and its plaintext removed) only after its producer
// signalled completion (finalized=1).
func TestIngestRequiresFinalized(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "nmap.xml")
	if err := os.WriteFile(f, []byte("<nmaprun></nmaprun>"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1,1)`)
	db.Exec(`INSERT INTO commands(session_id, cmd_index, command, complete) VALUES(1,0,'nmap',1)`)
	if _, err := db.Exec(`INSERT INTO command_artifacts(session_id, cmd_index, tool, path, finalized, ingested) VALUES(1,0,'nmap',?,0,0)`, f); err != nil {
		t.Fatal(err)
	}

	if n, _ := st.IngestArtifacts(1); n != 0 {
		t.Fatalf("ingested %d before finalize, want 0", n)
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatal("un-finalized file must not be removed")
	}

	db.Exec(`UPDATE command_artifacts SET finalized=1 WHERE session_id=1`)
	if n, _ := st.IngestArtifacts(1); n != 1 {
		t.Fatalf("ingested %d after finalize, want 1", n)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("finalized file must be removed after ingest")
	}
}

// Regression: an nmap interrupted with Ctrl-C leaves XML without closing tags.
// That file used to make IngestArtifacts fail on every call — breaking serve,
// open, report, export and parse for good — and its plaintext stayed on disk.
// Now it is ingested (damaged tail masked), removed from disk, the other
// artifacts are still processed, and the complete hosts are parsed.
func TestInterruptedScanDoesNotBreakIngest(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	partial := filepath.Join(dir, "nmap-partial.xml")
	good := filepath.Join(dir, "nmap-good.xml")
	os.WriteFile(partial, []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host><host><address addr="10.0.0.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="op`), 0o600)
	os.WriteFile(good, []byte(`<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>`), 0o600)
	db := st.DB()
	db.Exec(`INSERT OR IGNORE INTO sessions(id, started_at) VALUES(1,1)`)
	db.Exec(`INSERT INTO commands(session_id, cmd_index, command, complete) VALUES(1,0,'nmap',1)`)
	db.Exec(`INSERT INTO commands(session_id, cmd_index, command, complete) VALUES(1,1,'nmap',1)`)
	db.Exec(`INSERT INTO command_artifacts(session_id, cmd_index, tool, path, finalized, ingested) VALUES(1,0,'nmap',?,1,0)`, partial)
	db.Exec(`INSERT INTO command_artifacts(session_id, cmd_index, tool, path, finalized, ingested) VALUES(1,1,'nmap',?,1,0)`, good)

	n, err := st.IngestArtifacts(1)
	if err != nil || n != 2 {
		t.Fatalf("ingest: n=%d err=%v (want both artifacts, no error)", n, err)
	}
	for _, p := range []string{partial, good} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatalf("plaintext %s left on disk", p)
		}
	}
	if _, _, err := st.ParseArtifacts(1); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	rows, _ := db.Query(`SELECT value FROM entities WHERE type='host' ORDER BY value`)
	for rows.Next() {
		var v string
		rows.Scan(&v)
		hosts = append(hosts, v)
	}
	rows.Close()
	if len(hosts) != 2 || hosts[0] != "10.0.0.5" || hosts[1] != "10.0.0.9" {
		t.Fatalf("hosts = %v; want the completed host of the interrupted scan plus the good scan", hosts)
	}
}
