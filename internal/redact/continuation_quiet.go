package redact

// A conservative literal proof for further overlaps after overlap zero was
// quiet. Interior literals of any shortened context or of the row already
// occur in that first candidate. Only literals crossing the new join can be
// new; inspect at most maxLiteral-1 bytes on either side of that join.
//
// Restrict the cuts to a proven printable suffix (no CSI/UTF-8 boundary
// changes). There is no OSC in a quiet candidate. A failed proof always runs
// quietWith/lineTail normally. This cache is local to one finishLine call.
type continuationQuietCache struct {
	enabled       bool
	found         uint64
	width, rowLen int
	row           [64]byte
}

func (q *continuationQuietCache) init(context, row []byte, found uint64) {
	width := 0
	for _, lit := range foldedLits {
		width = max(width, len(lit))
	}
	width--
	if width < 0 || width > len(q.row) || !isASCII(row) || !continuationPlainSuffix(context, 64+width) {
		return
	}
	q.width = width
	q.found = found
	for i := 0; i < len(row) && q.rowLen < width; i++ {
		if row[i] == 27 && i+1 < len(row) && row[i+1] == '[' {
			j := i + 2
			for j < len(row) && (row[j] < 0x40 || row[j] > 0x7e) {
				j++
			}
			if j < len(row) {
				i = j
				continue
			}
		}
		if row[i] != '\r' {
			c := row[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			q.row[q.rowLen] = c
			q.rowLen++
		}
	}
	q.enabled = true
}

func (q *continuationQuietCache) quiet(context []byte, overlap int) bool {
	var boundary [128]byte
	end := len(context) - overlap
	start := max(0, end-q.width)
	n := 0
	for _, c := range context[start:end] {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		boundary[n] = c
		n++
	}
	n += copy(boundary[n:], q.row[:q.rowLen])
	found := q.found | litsFound(boundary[:n])
	for i := range patterns {
		if mayMatch(i, found) {
			return false
		}
	}
	return true
}
