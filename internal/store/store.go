// Package store is Layer 2: the single source of truth.
//
// Design contract (pillar #2 and #3):
//   - raw_chunks is append-only and is the ONLY source of truth. Every byte the
//     terminal emitted is here, in order, with a session-global byte offset.
//   - commands is a DERIVED view, reconstructable at any time by re-parsing
//     raw_chunks. A parser bug therefore never loses data: fix it, re-run.
//   - Production capture commits masked bytes plus the encrypted recovery state
//     before publishing output. The plain development build uses a writer queue.
//   - The database is opened with a passphrase. With the sqlcipher build tag the
//     whole file is encrypted (SQLCipher); the key lives only in memory.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/privatefs"
	"github.com/BeBorq/Pentrail/internal/redact"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	// The concrete "sqlite3" driver is registered by the build-tagged files
	// driver_plain.go (mattn, plain) and driver_cipher.go (SQLCipher).
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = FULL;
PRAGMA temp_store = MEMORY;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    started_at INTEGER NOT NULL,          -- unix nanoseconds
    ended_at   INTEGER,
    shell      TEXT,
    hostname   TEXT,
    version    TEXT,
    privacy_version TEXT NOT NULL DEFAULT '',
    unattributed_input INTEGER NOT NULL DEFAULT 0  -- typed-ahead lines not provably shell commands (CMD)
);

-- Append-only. The source of truth. Never updated, never deleted.
CREATE TABLE IF NOT EXISTS capture_events (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts INTEGER NOT NULL,
    recording INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_chunks (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    seq         INTEGER NOT NULL,         -- monotonic per session
    ts          INTEGER NOT NULL,         -- unix nanoseconds
    byte_offset INTEGER NOT NULL,         -- cumulative offset in the session's output stream
    data        BLOB    NOT NULL,
    redacted_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_raw_session_seq ON raw_chunks(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_raw_session_off ON raw_chunks(session_id, byte_offset);

-- Derived from the OSC-133 markers in the raw stream. Best-effort segmentation.
CREATE TABLE IF NOT EXISTS commands (
    id            INTEGER PRIMARY KEY,
    session_id    INTEGER NOT NULL REFERENCES sessions(id),
    cmd_index     INTEGER NOT NULL,       -- ordinal within the session
    command       TEXT,                   -- exact command line (base64-decoded from marker)
    cwd           TEXT,
    started_at    INTEGER,
    ended_at      INTEGER,
    exit_code     INTEGER,
    out_start_off INTEGER,                -- byte offset where this command's output begins
    out_end_off   INTEGER,                -- byte offset where it ends
    complete      INTEGER NOT NULL DEFAULT 0, -- 1 once the closing D marker was seen
    raw_missing   INTEGER NOT NULL DEFAULT 0  -- bytes missing from this command's raw range (gap/corruption)
);
CREATE INDEX IF NOT EXISTS idx_cmd_session ON commands(session_id, cmd_index);

-- Layer 3 output. Each entity is DERIVED from the raw log and carries full
-- provenance: which command revealed it, the byte offset in the raw stream,
-- when, by which tool, and with what confidence. Re-running an extractor
-- replaces its own rows, so improving a rule and replaying never loses data.
CREATE TABLE IF NOT EXISTS entities (
    id                INTEGER PRIMARY KEY,
    session_id        INTEGER NOT NULL REFERENCES sessions(id),
    type              TEXT    NOT NULL,   -- host, domain, url, email, ...
    value             TEXT    NOT NULL,
    confidence        TEXT    NOT NULL,   -- high / medium / low
    source_command_id INTEGER,            -- commands.id that revealed it
    source_offset     INTEGER,            -- byte offset in the raw stream
    tool              TEXT,               -- best-effort: the command's program
    discovered_at     INTEGER,            -- unix nanoseconds
    extractor         TEXT,               -- rule that produced it, e.g. regex:host / parser:nmap
    details           TEXT,               -- optional JSON: structured attributes (port state, service, severity)
    artifact_ref      TEXT,               -- sha256 of the structured artifact this came from (parser entities)
    obs_key           TEXT,               -- stable per-observation identity (lets regex+parser coexist)
    UNIQUE(session_id, obs_key)
);
CREATE INDEX IF NOT EXISTS idx_ent_session ON entities(session_id);
CREATE INDEX IF NOT EXISTS idx_ent_cmd     ON entities(source_command_id);

-- Structured output files produced by a wrapped tool during capture (nmap -oX,
-- ffuf -o, nuclei -jsonl). The high-confidence parser (Layer 3) reads these
-- offline. Linked to a command by its ordinal index within the session.
CREATE TABLE IF NOT EXISTS command_artifacts (
    id         INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    cmd_index  INTEGER NOT NULL,
    tool       TEXT    NOT NULL,
    path       TEXT    NOT NULL,
    created_at INTEGER,
    sha256     TEXT,                 -- of the ingested content
    length     INTEGER,              -- bytes
    content    BLOB,                 -- the structured output, encrypted at rest with the DB
    ingested   INTEGER NOT NULL DEFAULT 0,
    finalized  INTEGER NOT NULL DEFAULT 0,  -- the producing tool has finished writing (FIN marker)
    -- import outcome, persisted so it is visible in the viewer/report/export
    state           TEXT    NOT NULL DEFAULT '',  -- see artifact states in ingest.go
    state_detail    TEXT    NOT NULL DEFAULT '',
    partial         INTEGER NOT NULL DEFAULT 0,   -- content is a recovered prefix, not the whole file
    src_sha256      TEXT,                         -- sha256 of the ORIGINAL file bytes that were imported
    src_size        INTEGER,
    src_identity    TEXT,                         -- filesystem identity (dev:ino / volume:index)
    src_mtime       INTEGER,
    cleanup_pending INTEGER NOT NULL DEFAULT 0,   -- imported; plaintext original not yet removed
    cleanup_detail  TEXT    NOT NULL DEFAULT '',
    UNIQUE(session_id, cmd_index, tool, path)
);
CREATE INDEX IF NOT EXISTS idx_art_session ON command_artifacts(session_id);

-- Accountability layer: commands the operator ran that changed state on the
-- target, for the end-of-engagement cleanup checklist. Derived from commands,
-- idempotently rebuilt. Revert status is tracked per-viewer in the UI.
CREATE TABLE IF NOT EXISTS changes (
    id                INTEGER PRIMARY KEY,
    session_id        INTEGER NOT NULL REFERENCES sessions(id),
    cmd_index         INTEGER NOT NULL,
    source_command_id INTEGER,
    command           TEXT,
    cwd               TEXT,
    category          TEXT    NOT NULL,
    description       TEXT,
    detected_at       INTEGER,
    source_offset     INTEGER,
    UNIQUE(session_id, cmd_index, category)
);
CREATE INDEX IF NOT EXISTS idx_changes_session ON changes(session_id);

-- Per-database values (Codex 04J): view_namespace is a random identifier
-- made once when the database is first opened by this version. It names
-- THIS database in the viewer's per-browser state (cleanup checklist), so
-- a different database with the same session/command/category never
-- inherits it. Random: carries no path, key or token.
CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Operator notes (notes.go): the operator's own annotations written in the
-- viewer, NOT captured evidence. Additive: an older version ignores this
-- table. Recognized secrets are masked before a row is written; rows are
-- archived/restored (revision-checked), never deleted. Nothing here refers
-- to or changes commands, raw chunks, entities or capture state.
CREATE TABLE IF NOT EXISTS notes (
    id           TEXT    PRIMARY KEY,
    session_id   INTEGER NOT NULL REFERENCES sessions(id),
    anchor_kind  TEXT    NOT NULL DEFAULT '',
    cmd_index    INTEGER,
    node_id      TEXT,
    anchor_label TEXT    NOT NULL DEFAULT '',
    title        TEXT    NOT NULL DEFAULT '',
    body         TEXT    NOT NULL DEFAULT '',
    masked_bytes INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    revision     INTEGER NOT NULL DEFAULT 1,
    archived     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notes_session ON notes(session_id, updated_at);
`

// migrate adds columns introduced after a database was first created (ignoring
// "duplicate column" errors) and then rebuilds the entities constraint if the
// database predates it. A rebuild failure IS propagated — a half-migrated
// schema must not be used.
func migrate(db *sql.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE sessions ADD COLUMN privacy_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN unattributed_input INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE raw_chunks ADD COLUMN redacted_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE entities ADD COLUMN artifact_ref TEXT`,
		`ALTER TABLE entities ADD COLUMN obs_key TEXT`,
		`ALTER TABLE command_artifacts ADD COLUMN sha256 TEXT`,
		`ALTER TABLE command_artifacts ADD COLUMN length INTEGER`,
		`ALTER TABLE command_artifacts ADD COLUMN content BLOB`,
		`ALTER TABLE command_artifacts ADD COLUMN ingested INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE command_artifacts ADD COLUMN finalized INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE command_artifacts ADD COLUMN state TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE command_artifacts ADD COLUMN state_detail TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE command_artifacts ADD COLUMN partial INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE command_artifacts ADD COLUMN src_sha256 TEXT`,
		`ALTER TABLE command_artifacts ADD COLUMN src_size INTEGER`,
		`ALTER TABLE command_artifacts ADD COLUMN src_identity TEXT`,
		`ALTER TABLE command_artifacts ADD COLUMN src_mtime INTEGER`,
		`ALTER TABLE command_artifacts ADD COLUMN cleanup_pending INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE command_artifacts ADD COLUMN cleanup_detail TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE command_artifacts ADD COLUMN cleanup_quarantine TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE command_artifacts ADD COLUMN cleanup_dir TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE commands ADD COLUMN raw_missing INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE commands ADD COLUMN end_reason TEXT NOT NULL DEFAULT ''`,
	} {
		// Only a pre-existing column is an acceptable (expected) failure; any
		// other error means the schema is wrong and must be surfaced.
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("migrate add column: %w", err)
		}
	}
	return migrateEntitiesConstraint(db)
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// migrateEntitiesConstraint rebuilds the entities table when it still carries
// the OLD uniqueness rule (session_id, type, value, source_command_id). Under
// that rule a low-confidence regex row blocks the high-confidence parser row for
// the same value+command. SQLite cannot drop a constraint with ALTER, so the
// table is recreated with UNIQUE(session_id, obs_key) and its rows copied over
// (computing an obs_key for any legacy row that lacks one).
// migFailBeforeCommit is a test-only seam to force a failure AFTER the rebuild
// statements (including DROP TABLE) but before COMMIT, to prove the rollback
// restores the original table at a late stage.
var migFailBeforeCommit bool

func migrateEntitiesConstraint(db *sql.DB) (rerr error) {
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='entities'`).Scan(&ddl); err != nil {
		return nil // no entities table yet; the schema create handles it
	}
	if !strings.Contains(ddl, "UNIQUE(session_id, type, value, source_command_id)") {
		return nil // already migrated (or a newer form) — nothing to do
	}

	ctx := context.Background()
	// A single dedicated connection, so toggling foreign_keys (a per-connection
	// pragma) and the transaction below act on the SAME connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// foreign_keys can only be changed outside a transaction. Turn enforcement
	// off for the rebuild and ALWAYS restore it, even if the rebuild fails — and
	// surface a restore failure if nothing else already failed.
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer func() {
		if _, e := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); e != nil && rerr == nil {
			rerr = fmt.Errorf("restoring foreign_keys: %w", e)
		}
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback() // atomic: no half-rebuilt schema is left behind
		}
	}()

	stmts := []string{
		`CREATE TABLE entities_new (
            id                INTEGER PRIMARY KEY,
            session_id        INTEGER NOT NULL REFERENCES sessions(id),
            type              TEXT    NOT NULL,
            value             TEXT    NOT NULL,
            confidence        TEXT    NOT NULL,
            source_command_id INTEGER,
            source_offset     INTEGER,
            tool              TEXT,
            discovered_at     INTEGER,
            extractor         TEXT,
            details           TEXT,
            artifact_ref      TEXT,
            obs_key           TEXT,
            UNIQUE(session_id, obs_key)
        )`,
		// INSERT OR IGNORE: if two legacy rows collapse to the same computed key
		// (an edge case with NULL source_command_id), dropping the duplicate is
		// safe — the next extract/parse pass rewrites these rows anyway.
		`INSERT OR IGNORE INTO entities_new
            (id,session_id,type,value,confidence,source_command_id,source_offset,tool,discovered_at,extractor,details,artifact_ref,obs_key)
         SELECT id,session_id,type,value,confidence,source_command_id,source_offset,tool,discovered_at,extractor,details,artifact_ref,
            COALESCE(obs_key,
                     COALESCE(extractor,'') || char(31) || type || char(31) || value || char(31) || COALESCE(source_command_id,0))
         FROM entities`,
		`DROP TABLE entities`,
		`ALTER TABLE entities_new RENAME TO entities`,
		`CREATE INDEX IF NOT EXISTS idx_ent_session ON entities(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ent_cmd     ON entities(source_command_id)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("entities constraint migration: %w", err)
		}
	}
	if migFailBeforeCommit {
		return fmt.Errorf("injected late migration failure (test)") // -> rollback
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entities constraint migration commit: %w", err)
	}
	committed = true
	return nil
}

// Command is a derived record. Fields may be zero when markers are absent
// (e.g. inside ssh, msfconsole, a subshell): the raw bytes are still complete.
type Command struct {
	SessionID   int64
	Index       int64
	Command     string
	Cwd         string
	StartedAt   int64
	EndedAt     int64
	ExitCode    int64
	OutStartOff int64
	OutEndOff   int64
	Complete    bool
	// EndReason is empty when the end was observed (marker/prompt). Otherwise
	// the end was NOT observed and OutEndOff is only where capture of this
	// command stopped; the exit status is unknown.
	EndReason string
}

// End reasons for commands whose end was not observed.
const (
	EndSessionEnded     = "session_end"         // shell/terminal ended (EOF) with the command still open
	EndRecordingPaused  = "recording_paused"    // `pentrail off` while the command ran
	EndCaptureRecovered = "capture_interrupted" // capture process died; range recovered at restart
)

type rawEvent struct {
	sessionID int64
	seq       int64
	ts        int64
	offset    int64
	data      []byte // owned, sanitized copy
	redacted  int64
}

type Store struct {
	db                     *sql.DB
	identity               string
	viewNamespace          string
	file                   os.FileInfo // registered in openFiles; nil for :memory:
	path                   string
	ownerID, ownerIdentity string
	ownerPID               int
	privacyMu              sync.Mutex
	commandMu              sync.Mutex
	privacy                map[int64]*privacyStream
	noteMu                 sync.Mutex // serializes note changes; see noteWrite
	lastNoteCommit         time.Time  // when this Store last committed a note change
	stopping               chan struct{}
	syncCh                 chan chan error

	rawCh chan rawEvent
	cmdCh chan Command
	artCh chan artRef

	wg        sync.WaitGroup
	closed    chan struct{}
	closeErr  error
	closeOnce sync.Once

	// drainErr is set if the writer goroutine ever fails to persist a raw
	// chunk. Raw persistence is the one thing that must not fail silently.
	mu       sync.Mutex
	writeErr error
}

// Open opens (creating if needed) the encrypted database at path. passphrase is
// applied before any statement runs; see driver_*.go for what it does per build.
func Open(path string, passphrase []byte) (*Store, error) {
	// openDB is build-specific: plain SQLite (driver_plain.go) or SQLCipher
	// with every connection keyed via a ConnectHook (driver_cipher.go).
	sides := []string{path + "-wal", path + "-shm"}
	var fileKey os.FileInfo
	if path != ":memory:" {
		// A second Store of a database already open in THIS process must not
		// open/close extra descriptors of it: on POSIX that drops every fcntl
		// lock the process holds on the file, including the first Store's
		// lock on -shm (Codex iteration 02, finding 4). Its files were
		// secured by the first Open, so the second one skips that step.
		openFiles.Lock()
		defer openFiles.Unlock()
		alreadyOpen := false
		if fi, err := os.Stat(path); err == nil && openFiles.find(fi) != nil {
			alreadyOpen = true
		}
		if !alreadyOpen {
			if e := privatefs.PrepareDB(path); e != nil {
				return nil, e
			}
			// Side files are secured BEFORE SQLite opens the database. On
			// POSIX systems closing ANY descriptor of a file drops ALL of
			// this process's fcntl locks on it — including the lock by which
			// SQLite tells other processes that this connection uses the
			// shared WAL index (-shm). Protecting -shm after the open released
			// that lock, so the next process to open the database (another
			// terminal, extract, report, the viewer) reset the index under
			// the running session: SIGBUS in the session server or a
			// corrupted index. SQLite creates missing side files with the
			// database file's 0600 mode.
			if e := protectSideFiles(sides); e != nil {
				return nil, e
			}
		}
		defer func() {
			if fileKey != nil { // set only once the Store is fully open
				openFiles.add(fileKey)
			}
		}()
	}
	db, err := openDB(path, passphrase)
	if err != nil {
		return nil, err
	}
	// One writer connection keeps ordering deterministic and avoids lock churn.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema (wrong passphrase, or not an encrypted db?): %w", err)
	}
	if err := migrate(db); err != nil { // columns + entities-constraint rebuild
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	if path != ":memory:" {
		fi, err := os.Stat(path)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("database %s vanished while opening: %w", path, err)
		}
		fileKey = fi
	}
	if path != ":memory:" && runtime.GOOS == "windows" {
		// Windows locks belong to handles, not processes, so newly created
		// side files can be given the private DACL now without side effects.
		if e := protectSideFiles(sides); e != nil {
			db.Close()
			fileKey = nil
			return nil, e
		}
	}
	ns, err := ensureViewNamespace(db)
	if err != nil {
		db.Close()
		fileKey = nil
		return nil, fmt.Errorf("database view namespace: %w", err)
	}
	s := &Store{
		db: db, identity: dbidentity.ID(path), viewNamespace: ns, file: fileKey, path: path,
		rawCh:  make(chan rawEvent, 8192), // generous buffer; see WriteRaw
		cmdCh:  make(chan Command, 1024),
		artCh:  make(chan artRef, 256),
		closed: make(chan struct{}), stopping: make(chan struct{}), syncCh: make(chan chan error, 4), privacy: make(map[int64]*privacyStream),
	}
	if e := s.initRecovery(); e != nil {
		db.Close()
		fileKey = nil
		return nil, fmt.Errorf("recovery initialization: %w", e)
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *Store) StartSession(shell, host, version string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO sessions(started_at, shell, hostname, version,privacy_version) VALUES(?,?,?,?,?)`,
		time.Now().UnixNano(), shell, host, version, redact.Version)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) EndSession(id int64) error {
	ts := time.Now().UnixNano()
	return retryBusy("session end", func() error {
		_, err := s.db.Exec(`UPDATE sessions SET ended_at=? WHERE id=?`, ts, id)
		return err
	})
}

// enqueueRaw is used only by the plain development build.
//
// The channel is large. In the normal case the send does not block. If the
// writer ever falls far enough behind to fill the buffer, this blocks rather
// than drop bytes: for the source of truth, a momentary stall in the terminal
// is the correct trade against silent data loss. (Terminal output rates make
// this practically unreachable against local SQLite; it is a safety floor.)
func (s *Store) enqueueRaw(sessionID, seq, offset int64, data []byte, redacted int64) {
	cp := make([]byte, len(data))
	copy(cp, data)
	ev := rawEvent{sessionID: sessionID, seq: seq, ts: time.Now().UnixNano(), offset: offset, data: cp, redacted: redacted}
	select {
	case <-s.stopping:
	case s.rawCh <- ev:
	}
}

// WriteCommand never silently drops metadata: backpressure preserves commands.
func (s *Store) WriteCommand(c Command) {
	c.Command = redact.String(c.Command)
	c.Cwd = redact.String(c.Cwd)
	if Encrypted() {
		if e := retryBusy("command metadata", func() error { return s.upsertCommand(c) }); e != nil {
			s.setWriteErr(e)
		}
		return
	}
	select {
	case <-s.closed:
	case s.cmdCh <- c:
	}
}

type artRef struct {
	sessionID int64
	cmdIndex  int64
	tool      string
	path      string
	finalize  bool // false = record the artifact; true = mark it finished
}

// WriteArtifact preserves producer metadata, applying backpressure if necessary.
func (s *Store) WriteArtifact(sessionID, cmdIndex int64, tool, path string) {
	if Encrypted() {
		a := artRef{sessionID: sessionID, cmdIndex: cmdIndex, tool: tool, path: path}
		if e := retryBusy("artifact metadata", func() error { return s.upsertArtifact(a) }); e != nil {
			s.setWriteErr(e)
		}
		return
	}
	select {
	case <-s.closed:
	case s.artCh <- artRef{sessionID: sessionID, cmdIndex: cmdIndex, tool: tool, path: path}:
	}
}

// MarkArtifactFinalized records that the producing tool has finished writing the
// file at path, so the importer may safely ingest and remove it. Ordered after
// the matching WriteArtifact via the same channel.
func (s *Store) MarkArtifactFinalized(sessionID int64, path string) {
	if Encrypted() {
		a := artRef{sessionID: sessionID, path: path, finalize: true}
		if e := retryBusy("artifact metadata", func() error { return s.upsertArtifact(a) }); e != nil {
			s.setWriteErr(e)
		}
		return
	}
	select {
	case <-s.closed:
	case s.artCh <- artRef{sessionID: sessionID, path: path, finalize: true}:
	}
}

func (s *Store) writer() {
	defer s.wg.Done()

	const batchMax = 256
	flush := time.NewTicker(50 * time.Millisecond)
	defer flush.Stop()

	batch := make([]rawEvent, 0, batchMax)

	// persist writes the current batch, RETRYING with backoff until it succeeds
	// or a shutdown is signalled. It never clears the batch on failure, so raw
	// bytes are not dropped; while it retries, the writer stops draining rawCh,
	// so WriteRaw blocks and the terminal stalls — a visible failure state that
	// is the correct trade for an evidence tool. (Pillar #1.)
	first := true
	persist := func() {
		if len(batch) == 0 {
			return
		}
		backoff := 50 * time.Millisecond
		for {
			if err := s.flushRaw(batch); err == nil {
				if !first {
					fmt.Fprintln(os.Stderr, "pentrail: raw write recovered")
					s.clearWriteErr()
					first = true
				}
				batch = batch[:0]
				return
			} else {
				s.setWriteErr(err)
				if first {
					fmt.Fprintln(os.Stderr, "pentrail: RAW WRITE FAILED — retrying to avoid losing evidence; the terminal will stall:", err)
					first = false
				}
			}
			select {
			case <-s.closed:
				return // let the drain path make bounded final attempts
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}

	// finalPersist makes a bounded number of attempts at shutdown, then gives up
	// and records definitive evidence loss rather than hanging Close() forever.
	finalPersist := func() {
		if len(batch) == 0 {
			return
		}
		for attempt := 1; attempt <= 6; attempt++ {
			if err := s.flushRaw(batch); err == nil {
				batch = batch[:0]
				return
			} else {
				s.setWriteErr(err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprintf(os.Stderr, "pentrail: GAVE UP persisting final raw batch (%d chunks); evidence is INCOMPLETE\n", len(batch))
	}

	for {
		select {
		case ev := <-s.rawCh:
			batch = append(batch, ev)
			if len(batch) >= batchMax {
				persist()
			}
		case c := <-s.cmdCh:
			persist() // keep raw ordering ahead of derived rows
			if err := s.upsertCommand(c); err != nil {
				s.setWriteErr(err)
			}
		case a := <-s.artCh:
			if err := s.upsertArtifact(a); err != nil {
				s.setWriteErr(err)
			}
		case ack := <-s.syncCh:
		drainSync:
			for {
				select {
				case ev := <-s.rawCh:
					batch = append(batch, ev)
				case c := <-s.cmdCh:
					if e := s.upsertCommand(c); e != nil {
						s.setWriteErr(e)
					}
				case a := <-s.artCh:
					if e := s.upsertArtifact(a); e != nil {
						s.setWriteErr(e)
					}
				default:
					break drainSync
				}
			}
			persist()
			ack <- s.WriteError()
		case <-flush.C:
			persist()
		case <-s.closed:
			// Drain everything still queued before exiting.
			for {
				select {
				case ev := <-s.rawCh:
					batch = append(batch, ev)
					if len(batch) >= batchMax {
						finalPersist()
					}
				default:
					finalPersist()
					for {
						select {
						case c := <-s.cmdCh:
							if err := s.upsertCommand(c); err != nil {
								s.setWriteErr(err)
							}
						case a := <-s.artCh:
							if err := s.upsertArtifact(a); err != nil {
								s.setWriteErr(err)
							}
						default:
							return
						}
					}
				}
			}
		}
	}
}

func (s *Store) flushRaw(batch []rawEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO raw_chunks(session_id, seq, ts, byte_offset, data,redacted_bytes) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, ev := range batch {
		if _, err := stmt.Exec(ev.sessionID, ev.seq, ev.ts, ev.offset, ev.data, ev.redacted); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	stmt.Close()
	return tx.Commit()
}

func (s *Store) upsertCommand(c Command) error {
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	comp := 0
	if c.Complete {
		comp = 1
	}
	args := []interface{}{c.Command, c.Cwd, nz(c.StartedAt), nz(c.EndedAt), c.ExitCode, c.OutStartOff, c.OutEndOff, comp, c.EndReason, c.SessionID, c.Index}
	result, err := s.db.Exec(`UPDATE commands SET command=?,cwd=?,started_at=?,ended_at=?,exit_code=?,out_start_off=?,out_end_off=?,complete=?,end_reason=? WHERE session_id=? AND cmd_index=?`, args...)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = s.db.Exec(`INSERT INTO commands(session_id,cmd_index,command,cwd,started_at,ended_at,exit_code,out_start_off,out_end_off,complete,end_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, c.SessionID, c.Index, c.Command, c.Cwd, nz(c.StartedAt), nz(c.EndedAt), c.ExitCode, c.OutStartOff, c.OutEndOff, comp, c.EndReason)

	return err
}

func (s *Store) upsertArtifact(a artRef) error {
	if a.finalize {
		// Mark finished by path. WriteArtifact is always queued before this on
		// the same channel, so the row exists by now.
		_, err := s.db.Exec(
			`UPDATE command_artifacts SET finalized=1 WHERE session_id=? AND path=?`,
			a.sessionID, a.path)
		return err
	}
	_, err := s.db.Exec(`
        INSERT OR IGNORE INTO command_artifacts(session_id, cmd_index, tool, path, created_at)
        VALUES(?,?,?,?,?)`,
		a.sessionID, a.cmdIndex, a.tool, a.path, time.Now().UnixNano())
	return err
}

// nz maps a zero timestamp to NULL for cleaner queries.
func nz(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func (s *Store) setWriteErr(err error) {
	s.mu.Lock()
	if s.writeErr == nil {
		s.writeErr = err
	}
	s.mu.Unlock()
}

func (s *Store) clearWriteErr() {
	s.mu.Lock()
	s.writeErr = nil
	s.mu.Unlock()
}

// WriteError returns the first persistence failure, if any. Callers should
// surface this loudly: it means the source of truth is incomplete.
func (s *Store) WriteError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeErr
}

// Close stops the writer, flushes what remains, and reports evidence loss. It
// returns a non-nil error if any raw bytes could not be persisted, so callers
// can exit non-zero instead of pretending the capture is complete.
func (s *Store) Close() error {
	return s.shutdown(nil)
}

// FinishSession drains capture metadata BEFORE ingesting finalized artifacts,
// then closes the DB. The session owner must stop all producers before calling.
func (s *Store) FinishSession(id int64) error {
	return s.shutdown(func() error {
		endErr := s.EndSession(id)
		_, ingestErr := s.IngestArtifacts(id)
		return errors.Join(endErr, ingestErr)
	})
}

func (s *Store) shutdown(finalize func() error) error {
	s.closeOnce.Do(func() {
		close(s.stopping)
		close(s.closed)
		s.wg.Wait()
		if Encrypted() {
			if e := s.finishDurablePrivacy(); e != nil {
				s.setWriteErr(e)
			}
		} else {
			pending := s.finishPrivacy()
			if len(pending) > 0 {
				if e := s.flushRaw(pending); e != nil {
					s.setWriteErr(e)
				}
			}
		}

		var finalErr, writeErr error
		if finalize != nil {
			finalErr = finalize()
		}
		if err := s.WriteError(); err != nil {
			writeErr = fmt.Errorf("raw capture INCOMPLETE — evidence may be missing: %w", err)
		}
		s.closeErr = errors.Join(writeErr, finalErr, s.db.Close())
		if s.file != nil {
			openFiles.release(s.file)
		}
	})
	return s.closeErr
}

// openFiles counts live Stores per database file in this process. Files are
// matched with os.SameFile on Stat results (device+inode on POSIX); stat
// does not open the file, so it cannot drop any lock.
var openFiles openRegistry

type openRegistry struct {
	sync.Mutex
	list []*openEntry
}

type openEntry struct {
	fi os.FileInfo
	n  int
}

// find and add/release must be called with the registry locked.
func (o *openRegistry) find(fi os.FileInfo) *openEntry {
	for _, e := range o.list {
		if os.SameFile(e.fi, fi) {
			return e
		}
	}
	return nil
}

func (o *openRegistry) add(fi os.FileInfo) {
	if e := o.find(fi); e != nil {
		e.n++
		return
	}
	o.list = append(o.list, &openEntry{fi: fi, n: 1})
}

func (o *openRegistry) release(fi os.FileInfo) {
	o.Lock()
	defer o.Unlock()
	for i, e := range o.list {
		if os.SameFile(e.fi, fi) {
			if e.n--; e.n <= 0 {
				o.list = append(o.list[:i], o.list[i+1:]...)
			}
			return
		}
	}
}

func protectSideFiles(sides []string) error {
	for _, side := range sides {
		if _, e := os.Lstat(side); e == nil {
			if e = privatefs.ProtectExisting(side); e != nil {
				return e
			}
		}
	}
	return nil
}

// DB exposes the handle for read-only tooling (inspect, timeline).
func (s *Store) DB() *sql.DB { return s.db }

// ensureViewNamespace returns the database's view namespace, creating it on
// the first open: 128 random bits, hex. Concurrent first opens agree (the
// first insert wins, every open reads the stored value).
func ensureViewNamespace(db *sql.DB) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("secure RNG unavailable: %w", err)
	}
	if err := retryBusy("view namespace", func() error {
		_, e := db.Exec(`INSERT OR IGNORE INTO db_meta(key, value) VALUES('view_namespace', ?)`, hex.EncodeToString(b[:]))
		return e
	}); err != nil {
		return "", err
	}
	var ns string
	if err := db.QueryRow(`SELECT value FROM db_meta WHERE key='view_namespace'`).Scan(&ns); err != nil {
		return "", err
	}
	if !validNamespace(ns) {
		return "", fmt.Errorf("stored view namespace is malformed")
	}
	return ns, nil
}

func validNamespace(ns string) bool {
	if len(ns) != 32 {
		return false
	}
	for _, c := range ns {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ViewNamespace names this database in the viewer's per-browser state: the
// same database keeps it across restarts; another database has another.
func (s *Store) ViewNamespace() string { return s.viewNamespace }
