package store

import "time"

type CaptureEvent struct {
	AtMs      int64 `json:"at_ms"`
	Recording bool  `json:"recording"`
	Offset    int64 `json:"offset"`
}

func (s *Store) ListCaptureEvents(id int64) ([]CaptureEvent, error) {
	rows, err := s.db.Query("SELECT ts,recording,byte_offset FROM capture_events WHERE session_id=? ORDER BY id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []CaptureEvent
	for rows.Next() {
		var e CaptureEvent
		var ns int64
		if err := rows.Scan(&ns, &e.Recording, &e.Offset); err != nil {
			return nil, err
		}
		e.AtMs = ns / 1000000
		events = append(events, e)
	}
	return events, rows.Err()
}

// Capture transitions are audit metadata, not fabricated terminal bytes.
func (s *Store) RecordCaptureState(id int64, enabled bool, offset int64) error {
	ts := time.Now().UnixNano()
	return retryBusy("capture state", func() error {
		_, err := s.db.Exec("INSERT INTO capture_events(session_id,ts,recording,byte_offset) VALUES(?,?,?,?)", id, ts, enabled, offset)
		return err
	})
}

// AddUnattributedInput counts input lines that were typed or pasted while a
// program was running and could not be proven to be shell commands (they may
// have been that program's input). Their text is not stored as commands; the
// terminal output remains in the full session record.
func (s *Store) AddUnattributedInput(id, n int64) {
	if n <= 0 {
		return
	}
	if e := retryBusy("session metadata", func() error {
		_, err := s.db.Exec("UPDATE sessions SET unattributed_input=unattributed_input+? WHERE id=?", n, id)
		return err
	}); e != nil {
		s.setWriteErr(e)
	}
}
