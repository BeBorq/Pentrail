package store

import (
	"context"
	"errors"
	"github.com/BeBorq/Pentrail/internal/redact"
	"time"
)

type privacyStream struct {
	stream                 redact.Stream
	offset, seq, accounted int64
	paused                 bool
}

func (s *Store) WriteRaw(id, seq, offset int64, b []byte) error {
	select {
	case <-s.stopping:
		return errors.New("capture store is stopping")
	default:
	}
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	select {
	case <-s.stopping:
		return errors.New("capture store is stopping")
	default:
	}
	if e := s.WriteError(); e != nil {
		return e
	}
	state := s.privacy[id]
	if state == nil {
		state = &privacyStream{offset: offset, seq: seq}
	}
	if Encrypted() {
		next, e := s.commitDurable(id, state, false, len(b), func(n *privacyStream) []byte { return n.stream.Feed(b) })
		if e != nil {
			s.setWriteErr(e)
			return e
		}
		s.privacy[id] = next
		return nil
	}
	s.privacy[id] = state
	clean := state.stream.Feed(b)
	s.emitPrivacy(id, state, clean)
	return nil
}

func (s *Store) emitPrivacy(id int64, state *privacyStream, b []byte) {
	if len(b) == 0 {
		return
	}
	n := state.stream.Changed - state.accounted
	state.accounted = state.stream.Changed
	s.enqueueRaw(id, state.seq, state.offset, b, n)
	state.offset += int64(len(b))
	state.seq++
}

// Before a pause, fail closed on a partial line; continuation after resume
// stays masked until LF, so splitting a credential at off/on cannot reveal it.
func (s *Store) MaskPendingRaw(id int64) error {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	if state := s.privacy[id]; state != nil && !state.paused {
		if Encrypted() {
			next, e := s.commitDurable(id, state, false, 0, func(n *privacyStream) []byte { return n.stream.Seal() })
			if e != nil {
				s.setWriteErr(e)
				return e
			}
			s.privacy[id] = next
		} else {
			s.emitPrivacy(id, state, state.stream.Seal())
		}
	}
	return nil
}

func (s *Store) finishPrivacy() []rawEvent {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	var out []rawEvent
	for id, state := range s.privacy {
		if state.paused {
			continue
		}
		b := state.stream.Finish()
		if len(b) > 0 {
			out = append(out, rawEvent{sessionID: id, seq: state.seq, offset: state.offset, ts: time.Now().UnixNano(), data: b, redacted: state.stream.Changed - state.accounted})
		}
	}
	return out
}
func (s *Store) Sync(ctx context.Context) error {
	ack := make(chan error, 1)
	select {
	case <-s.stopping:
		return errors.New("store is closing")
	case s.syncCh <- ack:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case e := <-ack:
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) ReadSafeRange(id, start, end int64) ([]byte, int64, error) {
	var version string
	if e := s.db.QueryRow("SELECT privacy_version FROM sessions WHERE id=?", id).Scan(&version); e != nil {
		return nil, 0, e
	}
	if version == redact.Version {
		return s.ReadRange(id, start, end)
	}
	if version == redact.VersionV2 {
		return s.readLegacyV2(id, start, end)
	}
	if end <= start {
		return nil, 0, nil
	}
	rows, e := s.db.Query("SELECT byte_offset,data FROM raw_chunks WHERE session_id=? ORDER BY byte_offset", id)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var stream redact.Stream
	var out []byte
	var cursor, emitted, missing int64
	appendClean := func(b []byte) {
		a, z := int64(0), int64(len(b))
		if emitted < start {
			a = start - emitted
		}
		if emitted+z > end {
			z = end - emitted
		}
		if z > a && a >= 0 {
			out = append(out, b[a:z]...)
		}
		emitted += int64(len(b))
	}
	for rows.Next() {
		var off int64
		var b []byte
		if e = rows.Scan(&off, &b); e != nil {
			return nil, 0, e
		}
		if off > cursor {
			appendClean(stream.Seal())
			if off > start {
				gapStart := cursor
				if gapStart < start {
					gapStart = start
				}
				gapEnd := off
				if gapEnd > end {
					gapEnd = end
				}
				if gapEnd > gapStart {
					missing += gapEnd - gapStart
				}
			}
			emitted = off
			stream.FailClosedBoundary()
		}
		if cursor > off {
			skip := cursor - off
			if skip >= int64(len(b)) {
				continue
			}
			b = b[skip:]
			off = cursor
		}

		appendClean(stream.Feed(b))
		cursor = off + int64(len(b))
		if emitted >= end {
			break
		}
	}
	appendClean(stream.Finish())
	if cursor < end {
		a := cursor
		if a < start {
			a = start
		}
		missing += end - a
	}
	return out, missing, rows.Err()
}

func (s *Store) Identity() string { return s.identity }

func (s *Store) PauseCapture(id int64) error {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	if state := s.privacy[id]; state != nil {
		if Encrypted() {
			next, e := s.commitDurable(id, state, true, 0, func(n *privacyStream) []byte { return n.stream.Seal() })
			if e != nil {
				s.setWriteErr(e)
				return e
			}
			next.paused = true
			s.privacy[id] = next
		} else {
			s.emitPrivacy(id, state, state.stream.Seal())
			state.paused = true
		}
	}
	return nil
}

func (s *Store) ObservePaused(id int64, b []byte) {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	if state := s.privacy[id]; state != nil && state.paused {
		_ = state.stream.Feed(b)
		state.accounted = state.stream.Changed
	}
}
func (s *Store) ResumeCapture(id int64) {
	s.privacyMu.Lock()
	defer s.privacyMu.Unlock()
	if state := s.privacy[id]; state != nil && state.paused {
		state.stream.ResumeBoundary()
		state.accounted = state.stream.Changed
		state.paused = false
	}
}
