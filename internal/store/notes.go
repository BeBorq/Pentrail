package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// Operator notes: annotations written by the operator in the viewer. They are
// NOT captured evidence. They live in the same encrypted database (table
// notes, created additively by the schema), so encrypted backup, reopen and
// restore carry them. Writing a note never touches commands, raw chunks,
// entities, offsets, capture state or cleanup data: every statement below
// reads or writes the notes table only, besides reading the session,
// command and graph a new note is anchored to.
//
// Recognized secrets are masked with the same rules as the record
// (redact.Text) BEFORE a title, body or anchor label is stored; the masked
// byte count of the last save is kept and reported.
//
// Concurrency: every change names the revision it was based on; a change of
// an older revision is refused (ErrNoteConflict) instead of overwriting a
// newer one. Each change and the reply describing it are one transaction
// (noteWrite). Notes are archived and restored, never deleted.

const (
	NoteTitleMax  = 512       // bytes
	NoteBodyMax   = 64 << 10  // bytes
	NoteLabelMax  = 512       // bytes (anchor snapshot)
	NoteNodeIDMax = 2048      // bytes
	NotesPerList  = 10000     // rows returned by ListNotes
	noteIDBytes   = 16        // random identifier
	AnchorSession = ""        // the note belongs to the session as a whole
	AnchorCommand = "command" // a command of the session (cmd_index)
	AnchorNode    = "node"    // an element of the session's graph (exact node ID)
)

var (
	ErrNoteNotFound = errors.New("note not found")
	ErrNoteConflict = errors.New("the note was changed elsewhere")
	ErrNoteInvalid  = errors.New("invalid note")
)

// Note is one operator note. CmdIndex is set for a command anchor, NodeID for
// a graph-element anchor. AnchorLabel is a masked snapshot of what the anchor
// showed when the note was created; it stays if the anchor disappears.
type Note struct {
	ID          string `json:"id"`
	SessionID   int64  `json:"session_id"`
	AnchorKind  string `json:"anchor_kind"`
	CmdIndex    *int64 `json:"cmd_index,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	AnchorLabel string `json:"anchor_label"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	MaskedBytes int64  `json:"masked_bytes"`
	CreatedMs   int64  `json:"created_ms"`
	UpdatedMs   int64  `json:"updated_ms"`
	Revision    int64  `json:"revision"`
	Archived    bool   `json:"archived"`
}

// NoteAnchor names what a new note is attached to.
type NoteAnchor struct {
	Kind     string `json:"kind"`
	CmdIndex *int64 `json:"cmd_index,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNoteInvalid, fmt.Sprintf(format, a...))
}

// noteText checks the limits and masks recognized secrets.
func noteText(title, body string) (string, string, int64, error) {
	if !utf8.ValidString(title) || !utf8.ValidString(body) {
		return "", "", 0, invalid("text is not valid UTF-8")
	}
	if strings.ContainsRune(title, 0) || strings.ContainsRune(body, 0) {
		return "", "", 0, invalid("text contains a NUL character")
	}
	if len(title) > NoteTitleMax {
		return "", "", 0, invalid("the title is longer than %d bytes", NoteTitleMax)
	}
	if len(body) > NoteBodyMax {
		return "", "", 0, invalid("the text is longer than %d bytes", NoteBodyMax)
	}
	t, mt := redact.Text([]byte(title))
	b, mb := redact.Text([]byte(body))
	return string(t), string(b), mt + mb, nil
}

func newNoteID() (string, error) {
	b := make([]byte, noteIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure RNG unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// anchorLabel validates the anchor against the session's evidence and returns
// the snapshot shown later even if the anchor disappears.
func (s *Store) anchorLabel(sessionID int64, a NoteAnchor) (string, error) {
	switch a.Kind {
	case AnchorSession:
		if a.CmdIndex != nil || a.NodeID != "" {
			return "", invalid("a session note has no command or element")
		}
		return "session", nil
	case AnchorCommand:
		if a.CmdIndex == nil || *a.CmdIndex < 0 || a.NodeID != "" {
			return "", invalid("a command anchor needs a command number and nothing else")
		}
		var cmd sql.NullString
		err := s.db.QueryRow(`SELECT command FROM commands WHERE session_id=? AND cmd_index=?`, sessionID, *a.CmdIndex).Scan(&cmd)
		if err == sql.ErrNoRows {
			return "", invalid("command #%d is not in session %d", *a.CmdIndex, sessionID)
		}
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("command #%d: %s", *a.CmdIndex, clip(cmd.String, 400)), nil
	case AnchorNode:
		if a.CmdIndex != nil || a.NodeID == "" || len(a.NodeID) > NoteNodeIDMax || !utf8.ValidString(a.NodeID) {
			return "", invalid("an element anchor needs an exact graph element identifier and nothing else")
		}
		g, err := s.BuildGraph(sessionID)
		if err != nil {
			return "", err
		}
		for _, n := range g.Nodes {
			if n.ID == a.NodeID {
				return fmt.Sprintf("graph element (%s): %s", n.Type, clip(n.Label, 400)), nil
			}
		}
		return "", invalid("the element is not in the graph of session %d", sessionID)
	}
	return "", invalid("unknown anchor kind %q", a.Kind)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func (s *Store) sessionExists(id int64) error {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM sessions WHERE id=?`, id).Scan(&one)
	if err == sql.ErrNoRows {
		return invalid("session %d does not exist", id)
	}
	return err
}

// CreateNote stores a new note (revision 1).
func (s *Store) CreateNote(sessionID int64, a NoteAnchor, title, body string) (Note, error) {
	if err := s.sessionExists(sessionID); err != nil {
		return Note{}, err
	}
	t, b, masked, err := noteText(title, body)
	if err != nil {
		return Note{}, err
	}
	label, err := s.anchorLabel(sessionID, a)
	if err != nil {
		return Note{}, err
	}
	l, ml := redact.Text([]byte(label))
	label = clip(string(l), NoteLabelMax)
	_ = ml // the label is evidence already masked on read; masking again is defensive
	id, err := newNoteID()
	if err != nil {
		return Note{}, err
	}
	now := time.Now().UnixMilli()
	var node sql.NullString
	if a.Kind == AnchorNode {
		node = sql.NullString{String: a.NodeID, Valid: true}
	}
	var cmd sql.NullInt64
	if a.CmdIndex != nil {
		cmd = sql.NullInt64{Int64: *a.CmdIndex, Valid: true}
	}
	return s.noteWrite(sessionID, id, func(tx *sql.Tx) (sql.Result, error) {
		return tx.Exec(`INSERT INTO notes(id,session_id,anchor_kind,cmd_index,node_id,anchor_label,title,body,masked_bytes,created_at,updated_at,revision,archived)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,1,0)`, id, sessionID, a.Kind, cmd, node, label, t, b, masked, now, now)
	})
}

// testHookNoteWritten, if set (tests only), runs inside noteWrite after the
// change and before the row is read back.
var testHookNoteWritten func(id string)

// noteWrite runs one guarded change of a note and reads the row back IN THE
// SAME TRANSACTION, so the reply is exactly what this change committed and
// never a later write of another viewer. (SQLCipher 4.4 bundles SQLite 3.33,
// which has no RETURNING.) The transaction starts with the write, so it takes
// the write lock at once (no read-to-write upgrade); inside it only tx is
// used, as the store has a single connection. A change that touched no row
// is rolled back and reported as ErrNoteConflict with the current note (read
// in the same transaction) or as ErrNoteNotFound.
//
// While another connection (a recording session server, a second viewer)
// holds the database write lock for longer than SQLite's busy timeout, the
// change fails with SQLITE_BUSY/LOCKED ("database is locked") before anything
// is committed: the transaction is rolled back. Such a change is tried again
// from the start, with backoff, until it succeeds, fails otherwise, or
// noteBusyWindow has passed; then the lock error is returned. This is not a
// blind retry: a lock error means the change was not written, and the
// revision guard is evaluated again on each attempt. Every other error,
// ErrNoteConflict and ErrNoteNotFound are returned at once.
func (s *Store) noteWrite(sessionID int64, id string, change func(tx *sql.Tx) (sql.Result, error)) (Note, error) {
	start := time.Now()
	backoff := 50 * time.Millisecond
	for {
		n, err := s.noteWriteOnce(sessionID, id, change)
		if err == nil || !isBusy(err) || time.Since(start) >= noteBusyWindow {
			return n, err
		}
		time.Sleep(backoff)
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

// noteBusyWindow bounds how long a note change waits for another writer's
// lock (tests shorten it). A viewer save shows "Saving" meanwhile.
var noteBusyWindow = 30 * time.Second

func (s *Store) noteWriteOnce(sessionID int64, id string, change func(tx *sql.Tx) (sql.Result, error)) (Note, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Note{}, err
	}
	defer tx.Rollback()
	res, err := change(tx)
	if err != nil {
		return Note{}, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return Note{}, err
	}
	if testHookNoteWritten != nil {
		testHookNoteWritten(id)
	}
	n, err := scanNote(tx.QueryRow(`SELECT `+noteCols+` FROM notes WHERE id=? AND session_id=?`, id, sessionID))
	if err == sql.ErrNoRows {
		return Note{}, ErrNoteNotFound
	}
	if err != nil {
		return Note{}, err
	}
	if changed == 0 {
		return n, ErrNoteConflict
	}
	if err := tx.Commit(); err != nil {
		return Note{}, err
	}
	return n, nil
}

const noteCols = `id,session_id,anchor_kind,cmd_index,node_id,anchor_label,title,body,masked_bytes,created_at,updated_at,revision,archived`

func scanNote(sc interface{ Scan(...any) error }) (Note, error) {
	var n Note
	var cmd sql.NullInt64
	var node sql.NullString
	var archived int
	err := sc.Scan(&n.ID, &n.SessionID, &n.AnchorKind, &cmd, &node, &n.AnchorLabel, &n.Title, &n.Body, &n.MaskedBytes, &n.CreatedMs, &n.UpdatedMs, &n.Revision, &archived)
	if cmd.Valid {
		v := cmd.Int64
		n.CmdIndex = &v
	}
	n.NodeID = node.String
	n.Archived = archived != 0
	return n, err
}

// GetNote returns a note of the session (ErrNoteNotFound for another session).
func (s *Store) GetNote(sessionID int64, id string) (Note, error) {
	n, err := scanNote(s.db.QueryRow(`SELECT `+noteCols+` FROM notes WHERE id=? AND session_id=?`, id, sessionID))
	if err == sql.ErrNoRows {
		return Note{}, ErrNoteNotFound
	}
	return n, err
}

// ListNotes returns the session's notes, newest change first (archived ones too).
func (s *Store) ListNotes(sessionID int64) ([]Note, error) {
	rows, err := s.db.Query(`SELECT `+noteCols+` FROM notes WHERE session_id=? ORDER BY updated_at DESC, id LIMIT ?`, sessionID, NotesPerList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Note{}
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNote replaces the title and text of a note if it is still at
// revision base and not archived. On ErrNoteConflict the current note is
// returned so the caller can show it.
func (s *Store) UpdateNote(sessionID int64, id string, base int64, title, body string) (Note, error) {
	t, b, masked, err := noteText(title, body)
	if err != nil {
		return Note{}, err
	}
	return s.noteWrite(sessionID, id, func(tx *sql.Tx) (sql.Result, error) {
		return tx.Exec(`UPDATE notes SET title=?, body=?, masked_bytes=?, updated_at=?, revision=revision+1
		WHERE id=? AND session_id=? AND revision=? AND archived=0`, t, b, masked, time.Now().UnixMilli(), id, sessionID, base)
	})
}

// SetNoteArchived archives or restores a note at revision base.
func (s *Store) SetNoteArchived(sessionID int64, id string, base int64, archived bool) (Note, error) {
	v := 0
	if archived {
		v = 1
	}
	return s.noteWrite(sessionID, id, func(tx *sql.Tx) (sql.Result, error) {
		return tx.Exec(`UPDATE notes SET archived=?, updated_at=?, revision=revision+1
		WHERE id=? AND session_id=? AND revision=? AND archived<>?`, v, time.Now().UnixMilli(), id, sessionID, base, v)
	})
}
