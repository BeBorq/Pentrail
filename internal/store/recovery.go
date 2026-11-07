package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/redact"
	"os"
	"time"
)

const recoverySchema = `CREATE TABLE IF NOT EXISTS capture_checkpoints(session_id INTEGER PRIMARY KEY REFERENCES sessions(id),owner_id TEXT NOT NULL,owner_pid INTEGER NOT NULL,owner_identity TEXT NOT NULL,updated_ns INTEGER NOT NULL,pending_bytes INTEGER NOT NULL,state BLOB NOT NULL);CREATE TABLE IF NOT EXISTS capture_recoveries(id INTEGER PRIMARY KEY,session_id INTEGER NOT NULL REFERENCES sessions(id),recovered_ns INTEGER NOT NULL,byte_offset INTEGER NOT NULL);`

type captureCheckpoint struct {
	Stream                 redact.Checkpoint
	Offset, Seq, Accounted int64
}

func (s *Store) initRecovery() error {
	if _, e := s.db.Exec(recoverySchema); e != nil {
		return e
	}
	if !Encrypted() {
		return nil
	}
	var token [16]byte
	if _, e := rand.Read(token[:]); e != nil {
		return fmt.Errorf("recovery owner randomness: %w", e)
	}
	s.ownerID = hex.EncodeToString(token[:])
	s.ownerPID = os.Getpid()
	var e error
	s.ownerIdentity, e = processIdentity(s.ownerPID)
	if e != nil {
		return fmt.Errorf("recovery process identity: %w", e)
	}
	return s.recoverAbandoned()
}
func insertCapture(tx *sql.Tx, id int64, state *privacyStream, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	changed := state.stream.Changed - state.accounted
	_, e := tx.Exec(`INSERT INTO raw_chunks(session_id,seq,ts,byte_offset,data,redacted_bytes) VALUES(?,?,?,?,?,?)`, id, state.seq, time.Now().UnixNano(), state.offset, b, changed)
	if e != nil {
		return e
	}
	state.offset += int64(len(b))
	state.seq++
	state.accounted = state.stream.Changed
	return nil
}

// Persist the materialized bytes and the remaining original bytes atomically.
// The SQLCipher connection uses synchronous=FULL. No original checkpoint bytes
// are exposed by the viewer, exporters, or the sanitized backup.
func (s *Store) commitPrivacy(id int64, state *privacyStream, b []byte, final bool, ct *commitTimer) error {
	tx, e := s.db.Begin()
	ct.lap(cpBegin)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = insertCapture(tx, id, state, b); e != nil {
		return e
	}
	ct.lap(cpInsert)
	if final {
		_, e = tx.Exec("DELETE FROM capture_checkpoints WHERE session_id=?", id)
	} else {
		cp := captureCheckpoint{state.stream.Checkpoint(), state.offset, state.seq, state.accounted}
		data, err := json.Marshal(cp)
		if err != nil {
			return err
		}
		ct.lap(cpBuild)
		_, e = tx.Exec(`INSERT OR REPLACE INTO capture_checkpoints(session_id,owner_id,owner_pid,owner_identity,updated_ns,pending_bytes,state) VALUES(?,?,?,?,?,?,?)`, id, s.ownerID, s.ownerPID, s.ownerIdentity, time.Now().UnixNano(), len(cp.Stream.Pending), data)
	}
	ct.lap(cpUpsert)
	if e != nil {
		return e
	}
	e = tx.Commit()
	ct.lap(cpCommit)
	return e
}

// commitDurable derives the next privacy state from state with step and commits
// it, retrying while another process holds the database lock. Each attempt
// starts again from the untouched state: a failed transaction rolls back, but
// insertCapture has already advanced the in-memory offset/seq of that attempt's
// copy, so reusing it would shift every later byte offset.
func (s *Store) commitDurable(id int64, state *privacyStream, final bool, input int, step func(*privacyStream) []byte) (*privacyStream, error) {
	var out *privacyStream
	ct := startCommitTimer()
	stored, attempts := 0, 0
	err := retryBusy("capture write", func() error {
		if attempts++; attempts > 1 {
			ct.reset()
		}
		ct.stepBegin(&state.stream)
		next := *state
		next.stream = state.stream.Clone()
		clean := step(&next)
		ct.lap(cpStep)
		ct.stepEnd(len(clean))
		if e := s.commitPrivacy(id, &next, clean, final, ct); e != nil {
			return e
		}
		stored = len(clean)
		out = &next
		return nil
	})
	ct.done(input, stored)
	return out, err
}

func (s *Store) recoverAbandoned() error {
	rows, e := s.db.Query("SELECT session_id,owner_id,owner_pid,owner_identity,updated_ns,state FROM capture_checkpoints")
	if e != nil {
		return e
	}
	type record struct {
		id       int64
		owner    string
		pid      int
		identity string
		updated  int64
		data     []byte
	}
	var records []record
	for rows.Next() {
		var r record
		if e = rows.Scan(&r.id, &r.owner, &r.pid, &r.identity, &r.updated, &r.data); e != nil {
			rows.Close()
			return e
		}
		records = append(records, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, r := range records {
		identity, ownerErr := processIdentity(r.pid)
		if ownerErr == nil && identity == r.identity {
			continue
		}
		if ownerErr != nil && !processGone(ownerErr) {
			return fmt.Errorf("cannot safely check checkpoint owner: %w", ownerErr)
		}
		if len(r.data) > 200*1024 {
			return fmt.Errorf("oversized recovery checkpoint for session %d", r.id)
		}
		var cp captureCheckpoint
		if e = json.Unmarshal(r.data, &cp); e != nil {
			return fmt.Errorf("invalid recovery checkpoint for session %d", r.id)
		}
		if cp.Offset < 0 || cp.Seq < 0 || cp.Accounted < 0 {
			return fmt.Errorf("invalid recovery position")
		}
		stream, err := redact.Restore(cp.Stream)
		if err != nil {
			return err
		}
		state := &privacyStream{stream: stream, offset: cp.Offset, seq: cp.Seq, accounted: cp.Accounted}
		clean := state.stream.Finish()
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		res, err := tx.Exec("UPDATE capture_checkpoints SET owner_id=?,owner_pid=?,owner_identity=? WHERE session_id=? AND owner_id=? AND updated_ns=?", s.ownerID, s.ownerPID, s.ownerIdentity, r.id, r.owner, r.updated)
		if err != nil {
			tx.Rollback()
			return err
		}
		count, err := res.RowsAffected()
		if err != nil {
			tx.Rollback()
			return err
		}
		if count == 0 {
			tx.Rollback()
			continue
		}
		if err = insertCapture(tx, r.id, state, clean); err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.Exec("INSERT INTO capture_recoveries(session_id,recovered_ns,byte_offset) VALUES(?,?,?)", r.id, time.Now().UnixNano(), state.offset); err == nil {
			_, err = tx.Exec("UPDATE sessions SET ended_at=COALESCE(ended_at,?) WHERE id=?", r.updated, r.id)
		}
		if err == nil {
			_, err = tx.Exec("UPDATE commands SET out_end_off=MAX(COALESCE(out_end_off,0),?), end_reason=CASE WHEN end_reason='' THEN ? ELSE end_reason END WHERE id=(SELECT id FROM commands WHERE session_id=? ORDER BY cmd_index DESC,id DESC LIMIT 1) AND ended_at IS NULL", state.offset, EndCaptureRecovered, r.id)
		}
		if err == nil {
			_, err = tx.Exec("DELETE FROM capture_checkpoints WHERE session_id=? AND owner_id=?", r.id, s.ownerID)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) finishDurablePrivacy() error {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	for id, state := range s.privacy {
		if state.paused {
			continue
		}
		next, e := s.commitDurable(id, state, true, 0, func(n *privacyStream) []byte { return n.stream.Finish() })
		if e != nil {
			return e
		}
		s.privacy[id] = next
	}
	return nil
}
