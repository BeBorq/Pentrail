package store

import "github.com/BeBorq/Pentrail/internal/redact"

type RawSpan struct {
	Offset int64
	Data   []byte
}

func (s *Store) ReadSpans(id, start, end int64) ([]RawSpan, error) {
	spans, e := s.rawSpans(id, start, end)
	if e != nil {
		return nil, e
	}
	var version string
	if e = s.db.QueryRow("SELECT privacy_version FROM sessions WHERE id=?", id).Scan(&version); e != nil {
		return nil, e
	}
	if version == redact.Version {
		return spans, nil
	}
	for i := range spans {
		b, _, e := s.ReadSafeRange(id, spans[i].Offset, spans[i].Offset+int64(len(spans[i].Data)))
		if e != nil {
			return nil, e
		}
		spans[i].Data = b
	}
	return spans, nil
}

// rawSpans returns the stored bytes of [start,end) as contiguous spans, exactly
// as written (no read-time protection).
func (s *Store) rawSpans(id, start, end int64) ([]RawSpan, error) {
	rows, e := s.db.Query("SELECT byte_offset,data FROM raw_chunks WHERE session_id=? AND byte_offset<? AND byte_offset+length(data)>? ORDER BY byte_offset", id, end, start)
	if e != nil {
		return nil, e
	}
	var spans []RawSpan
	for rows.Next() {
		var off int64
		var data []byte
		if e = rows.Scan(&off, &data); e != nil {
			rows.Close()
			return nil, e
		}
		a, z := int64(0), int64(len(data))
		if off < start {
			a = start - off
		}
		if off+z > end {
			z = end - off
		}
		if z <= a {
			continue
		}
		off += a
		data = data[a:z]
		if len(spans) > 0 {
			last := &spans[len(spans)-1]
			lastEnd := last.Offset + int64(len(last.Data))
			if off <= lastEnd {
				skip := lastEnd - off
				if skip < int64(len(data)) {
					last.Data = append(last.Data, data[skip:]...)
				}
				continue
			}
		}
		spans = append(spans, RawSpan{Offset: off, Data: append([]byte(nil), data...)})
	}
	e = rows.Err()
	rows.Close()
	return spans, e
}

// readLegacyV2 serves masked-v2 data with the current marker rules applied.
// Only a bounded window around the range is read, so paging through a large
// old session stays linear.
func (s *Store) readLegacyV2(id, start, end int64) ([]byte, int64, error) {
	if end <= start {
		return nil, 0, nil
	}
	ws := start - redact.LegacyWindow
	if ws < 0 {
		ws = 0
	}
	spans, e := s.rawSpans(id, ws, end+redact.LegacyWindow)
	if e != nil {
		return nil, 0, e
	}
	var out []byte
	cursor, missing := start, int64(0)
	for _, sp := range spans {
		a, z := sp.Offset, sp.Offset+int64(len(sp.Data))
		if a < start {
			a = start
		}
		if z > end {
			z = end
		}
		if z <= a {
			continue
		}
		safe := redact.ProtectLegacyMarkers(sp.Data)
		if a > cursor {
			missing += a - cursor
		}
		out = append(out, safe[a-sp.Offset:z-sp.Offset]...)
		cursor = z
	}
	if cursor < end {
		missing += end - cursor
	}
	return out, missing, nil
}
