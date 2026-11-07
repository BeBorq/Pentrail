//go:build !sqlcipher

// These tests fabricate a legacy on-disk database with the raw sqlite3 driver
// and no key, then open it through the store to exercise the schema upgrade.
// That upgrade is a plaintext-era concern: under -tags sqlcipher the raw handle
// would write an unencrypted file that the keyed Open refuses for a different
// reason, so Open's error would no longer prove anything about the migration.
// The encrypted build path is covered by the keyed openTemp suite.
package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// oldEntitiesDDL is the entities table as an earlier build created it: the
// uniqueness rule that makes a regex row block a parser row, and no obs_key /
// artifact_ref columns.
const oldEntitiesDDL = `
CREATE TABLE sessions (id INTEGER PRIMARY KEY, started_at INTEGER);
CREATE TABLE commands (id INTEGER PRIMARY KEY, session_id INTEGER, cmd_index INTEGER);
CREATE TABLE entities (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    type TEXT NOT NULL, value TEXT NOT NULL, confidence TEXT NOT NULL,
    source_command_id INTEGER, source_offset INTEGER, tool TEXT,
    discovered_at INTEGER, extractor TEXT, details TEXT,
    UNIQUE(session_id, type, value, source_command_id)
);`

// P3 from the second review: opening a database created by the OLD schema must
// rebuild the entities constraint, so a low-confidence regex row no longer
// blocks the high-confidence parser row for the same value+command.
func TestLegacyEntitiesConstraintMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	// Build a legacy database directly.
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldEntitiesDDL); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`INSERT INTO sessions(id, started_at) VALUES(1,1)`)
	raw.Exec(`INSERT INTO commands(id, session_id, cmd_index) VALUES(1,1,0)`)
	// a low-confidence regex host for command 1
	if _, err := raw.Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,extractor)
	    VALUES(1,'host','10.0.0.1','low',1,'regex:host')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Open through the store: this runs the migration.
	st, err := Open(path, nil)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer st.Close()

	// Under the OLD constraint this INSERT would be rejected (same
	// session/type/value/source_command_id). After migration it must succeed,
	// because uniqueness is now on (session_id, obs_key).
	_, err = st.DB().Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,extractor,obs_key)
	    VALUES(1,'host','10.0.0.1','high',1,'parser:nmap','parser:nmap` + "\x1f" + `host` + "\x1f" + `10.0.0.1` + "\x1f" + `0')`)
	if err != nil {
		t.Fatalf("parser row still blocked after migration (constraint not rebuilt): %v", err)
	}

	var n int
	st.DB().QueryRow(`SELECT count(*) FROM entities WHERE type='host' AND value='10.0.0.1'`).Scan(&n)
	if n != 2 {
		t.Fatalf("host rows after migration: got %d, want 2 (legacy low + new high)", n)
	}
	// the legacy row must have survived with a non-null obs_key
	var legacyObs sql.NullString
	st.DB().QueryRow(`SELECT obs_key FROM entities WHERE confidence='low'`).Scan(&legacyObs)
	if !legacyObs.Valid || legacyObs.String == "" {
		t.Fatal("legacy row lost its obs_key during migration")
	}
}

// The rebuild must be atomic: if it fails partway, the original entities table
// must remain intact and Open must return an error (not use a half-migrated db).
func TestMigrationAtomicOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldEntitiesDDL); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`INSERT INTO sessions(id, started_at) VALUES(1,1)`)
	raw.Exec(`INSERT INTO entities(session_id,type,value,confidence,extractor) VALUES(1,'host','10.0.0.1','low','regex:host')`)
	// Pre-create entities_new so the migration's CREATE collides and fails.
	if _, err := raw.Exec(`CREATE TABLE entities_new (x)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	if _, err := Open(path, nil); err == nil {
		t.Fatal("expected Open to fail when the migration fails")
	}

	// The original entities table and its row must be intact (rolled back).
	raw2, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	var n int
	if err := raw2.QueryRow(`SELECT count(*) FROM entities`).Scan(&n); err != nil {
		t.Fatalf("entities table lost after a failed migration: %v", err)
	}
	if n != 1 {
		t.Fatalf("entities rows after failed migration: got %d, want 1 (rolled back)", n)
	}
}

// Prove rollback at a LATE stage: force a failure after the rebuild statements
// (including DROP TABLE entities) but before COMMIT. The DROP must be undone.
func TestMigrationRollbackAfterDrop(t *testing.T) {
	migFailBeforeCommit = true
	defer func() { migFailBeforeCommit = false }()

	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldEntitiesDDL); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`INSERT INTO sessions(id, started_at) VALUES(1,1)`)
	raw.Exec(`INSERT INTO entities(session_id,type,value,confidence,extractor) VALUES(1,'host','10.0.0.1','low','regex:host')`)
	raw.Close()

	if _, err := Open(path, nil); err == nil {
		t.Fatal("expected Open to fail (injected late failure)")
	}

	raw2, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	var n int
	if err := raw2.QueryRow(`SELECT count(*) FROM entities`).Scan(&n); err != nil {
		t.Fatalf("entities table dropped and not rolled back: %v", err)
	}
	if n != 1 {
		t.Fatalf("entities rows after late rollback: got %d, want 1", n)
	}
}
