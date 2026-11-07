package redact

import "bytes"

// A deterministic transformation can be reused only at a fixed context:
// identical raw line, identical complete context, and no PEM/next-line state
// before or after it. Every line is still emitted, and Changed is incremented
// for every occurrence. A different byte or state falls back to finishLine.
// This cache belongs to one Feed invocation, not Stream, Clone or checkpoints.
type repeatedLineCache struct {
	input, context, output []byte
	changed                int64
	valid                  bool
}

func (c *repeatedLineCache) matches(s *Stream) bool {
	return c.valid && !s.pem && !s.nextSecretLine &&
		bytes.Equal(c.input, s.pending) && bytes.Equal(c.context, s.context)
}
