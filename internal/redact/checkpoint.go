package redact

import (
	"bytes"
	"errors"
)

// Checkpoint retains incomplete bytes exactly. Context already materialized in
// raw_chunks is sanitized before it is copied into encrypted recovery storage.
type Checkpoint struct {
	Version                         int
	Pending, Prefix, Context        []byte
	PEM, ClosedLine, NextSecretLine bool
	Changed                         int64
}

func (s *Stream) Clone() Stream {
	c := *s
	c.pending = bytes.Clone(s.pending)
	c.prefix = bytes.Clone(s.prefix)
	c.context = bytes.Clone(s.context)
	return c
}

// Sizes: bytes held for an unfinished line, the line prefix and the
// recognition context (diagnostics; Codex 04K).
func (s *Stream) Sizes() (pending, prefix, context int) {
	return len(s.pending), len(s.prefix), len(s.context)
}

func (s *Stream) Checkpoint() Checkpoint {
	context, _ := Text(s.context)
	prefix, _ := Text(s.prefix)
	return Checkpoint{1, bytes.Clone(s.pending), prefix, context, s.pem, s.closedLine, s.nextSecretLine, s.Changed}
}
func Restore(c Checkpoint) (Stream, error) {
	if c.Version != 1 || len(c.Pending) > MaxLine || len(c.Prefix) > 512 || len(c.Context) > 4096 || c.Changed < 0 {
		return Stream{}, errors.New("invalid recovery checkpoint")
	}
	return Stream{pending: bytes.Clone(c.Pending), prefix: bytes.Clone(c.Prefix), context: bytes.Clone(c.Context), pem: c.PEM, closedLine: c.ClosedLine, nextSecretLine: c.NextSecretLine, Changed: c.Changed}, nil
}

// Paused input may affect masking decisions, but its bytes must never enter a
// later checkpoint when recording resumes.
func (s *Stream) ResumeBoundary() { _ = s.Seal(); s.pending = nil; s.prefix = nil; s.context = nil }
