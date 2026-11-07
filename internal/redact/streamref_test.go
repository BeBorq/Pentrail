package redact

// Codex 04L: the Stream's Feed and finishLine exactly as they were before
// the 04L allocation work (0.6.12, copied verbatim, renamed): the
// independent reference for TestPrefilterIsExact's stream check. Run with
// prefilterOff, every candidate overlap goes through line() with every
// pattern.

import "bytes"

func (s *Stream) feedRef(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		n := bytes.IndexByte(b, '\n')
		end := n >= 0
		if !end {
			n = len(b)
		} else {
			n++
		}
		piece := b[:n]
		b = b[n:]
		if s.closedLine {
			if len(s.prefix) < 512 {
				k := 512 - len(s.prefix)
				if k > len(piece) {
					k = len(piece)
				}
				s.prefix = append(s.prefix, piece[:k]...)
			}
			v := append([]byte(nil), piece...)
			mask(v)
			s.Changed += diff(piece, v)
			out = append(out, v...)
			if end {
				s.update(s.prefix)
				s.closedLine = false
				s.nextSecretLine = false
				s.prefix = nil
			}
			continue
		}
		s.pending = append(s.pending, piece...)
		if len(s.pending) > MaxLine {
			out = append(out, s.Timeout()...)
			if end {
				s.closedLine = false
				s.nextSecretLine = false
				s.prefix = nil
			}
			continue
		}
		if end {
			out = append(out, s.finishLineRef()...)
		}
	}
	return out
}
func (s *Stream) finishLineRef() []byte {
	b := s.pending
	s.pending = nil
	was := s.pem
	previousSecretLine := s.nextSecretLine
	s.nextSecretLine = false
	if isPrivateBegin(b) {
		s.pem = true
	}
	v := line(b)
	// ConPTY can redraw a wrapped label across CRLF and a cursor-position CSI.
	// Join only that redraw continuation for recognition; persist original byte offsets.
	continuation := cursorContinuation.Match(b)
	nextContext := append([]byte(nil), b...)
	if continuation && len(s.context) > 0 {
		head := cursorContinuation.ReplaceAll(b, nil)
		best := -1
		for overlap := 0; overlap <= min(64, min(len(head), len(s.context))); overlap++ {
			if overlap > 0 && !bytes.Equal(s.context[len(s.context)-overlap:], head[:overlap]) {
				continue
			}
			prefix := s.context[:len(s.context)-overlap]
			joined := append(append([]byte(nil), prefix...), b...)
			clean := line(joined)
			score := 0
			for i := range v {
				if clean[len(prefix)+i] == '*' && b[i] != '*' {
					v[i] = '*'
					score++
				}
			}
			if score > best {
				best = score
				nextContext = joined
			}
		}
	}

	nextContext = bytes.TrimRight(nextContext, "\r\n")
	if len(nextContext) > 4096 {
		nextContext = nextContext[len(nextContext)-4096:]
	}
	s.context = append(s.context[:0], nextContext...)
	if was || s.pem || isPrivateEnd(b) || previousSecretLine {
		mask(v)
	}
	s.update(b)
	if emptySecretLabel(b) {
		s.nextSecretLine = true
	}
	s.Changed += diff(b, v)
	return v
}
