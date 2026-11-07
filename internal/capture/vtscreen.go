package capture

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// vtScreen is a small, explicit terminal model: it applies the subset of
// VT/ECMA-48 that ConPTY emits (printable text with autowrap, CR, LF, BS,
// TAB, cursor positioning, erase in display/line, insert/delete, scrolling,
// save/restore cursor; OSC strings are passed to a callback) to a grid of
// cells. Codex iteration 04B: ConPTY repaints the console buffer in frames
// and passes OSC sequences through immediately, so byte order in the stream
// is not screen order. Segmentation is therefore done on what a terminal
// would show, with the raw offset of every write kept for provenance.
//
// Every printable write records, on the logical line it lands on, the raw
// offset of its first byte and the offset just after it; a logical line is
// a row plus the rows it autowrapped into.
//
// Memory is bounded (Codex 04C, finding 1): the model holds the visible
// screen only. A logical line keeps the rows it has ON the screen; when its
// first row leaves the screen (scrolled off, cleared) the row's text is moved
// into the line's head, which is capped at maxLineText. A single output line
// of any size (base64, minified JSON, binary text without LF) therefore costs
// at most one screen plus maxLineText. The raw stream itself is recorded by
// the session, not here: nothing is cut from the recording.
type vtScreen struct {
	w, h   int
	rows   []*vtRow
	cx, cy int
	wrap   bool // wrap pending (cursor written at the last column)
	sx, sy int  // saved cursor
	top    int  // scroll region [top, bot]
	bot    int

	// parser
	state    int
	params   []byte
	osc      []byte
	oscStart int64
	utf      []byte
	utfStart int64

	// noOffsets: the bytes being fed are not part of the recorded stream
	// (recording paused: the session's offset does not advance), so they
	// must not set any line's offsets.
	noOffsets bool

	onOSC   func(payload string, start, end int64)
	onWrite func(l *vtLine, start, end int64) // after a cell write
	// onScrollOff (tests only; nil in production, nothing is stored): a row
	// scrolled off the top. text is the finished logical line when this was
	// its last row on screen, "" for a blank row; ok is false while the line
	// still has rows on screen.
	onScrollOff func(text string, ok bool)
}

type vtRow struct {
	cells []string // "" = blank; wide runes leave a "\x00" placeholder after them
	line  *vtLine
	cont  bool // this row continues the previous row (autowrap)
}

// vtLine is a logical line: one or more rows joined by autowrap.
type vtLine struct {
	rows []*vtRow // its rows that are on the screen, in order (at most h)
	head string   // text of its first rows that left the screen, ≤ maxLineText
	// cut: part of the text is not kept (head reached maxLineText, or a row
	// other than the first left the screen); text() is then only a prefix
	// (plus what is on screen) and must not be taken as a whole command echo.
	cut               bool
	firstOff, lastEnd int64
	firstAt           int64
	seg               segLine // segmenter state
}

// maxLineText bounds the kept text of one logical line: a prompt (marker
// text ≤ 8 KiB) plus a typed command (≤ maxLineBytes) fit in it.
const maxLineText = 2*maxLineBytes + 4096

const (
	vtGround = iota
	vtEsc
	vtCSI
	vtOSC
	vtOSCEsc
	vtEscInter
)

func newVTScreen(w, h int) *vtScreen {
	s := &vtScreen{}
	s.resize(w, h)
	return s
}

func (s *vtScreen) resize(w, h int) {
	if w < 2 {
		w = 2
	}
	if h < 1 {
		h = 1
	}
	old := s.rows
	// rows that do not fit any more leave the screen at the top, in order
	for i := 0; i < len(old)-h; i++ {
		s.dropRow(old[i], false)
	}
	s.w, s.h = w, h
	s.rows = make([]*vtRow, h)
	for i := range s.rows {
		s.rows[i] = s.newRow()
	}
	// keep the bottom part of the old screen, row-aligned
	for i := 0; i < len(old) && i < h; i++ {
		src := old[len(old)-1-i]
		dst := s.rows[h-1-i]
		copy(dst.cells, src.cells)
		dst.line, dst.cont = src.line, src.cont
		if src.line != nil {
			for k, r := range src.line.rows {
				if r == src {
					src.line.rows[k] = dst
				}
			}
		}
	}
	s.top, s.bot = 0, h-1
	s.cx, s.cy = clamp(s.cx, 0, w-1), clamp(s.cy, 0, h-1)
	s.wrap = false
}

func (s *vtScreen) newRow() *vtRow { return &vtRow{cells: make([]string, s.w)} }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Feed processes b, whose first byte is at raw offset off.
func (s *vtScreen) Feed(b []byte, off int64, now int64) {
	for i := 0; i < len(b); i++ {
		s.byte1(b[i], off+int64(i), now)
	}
}

func (s *vtScreen) byte1(c byte, off int64, now int64) {
	switch s.state {
	case vtEsc:
		switch c {
		case '[':
			s.state, s.params = vtCSI, s.params[:0]
		case ']':
			s.state, s.osc, s.oscStart = vtOSC, s.osc[:0], off-1
		case '7':
			s.sx, s.sy, s.state = s.cx, s.cy, vtGround
		case '8':
			s.cx, s.cy, s.wrap, s.state = s.sx, s.sy, false, vtGround
		case 'M': // reverse index
			if s.cy == s.top {
				s.scrollDown(1)
			} else if s.cy > 0 {
				s.cy--
			}
			s.state = vtGround
		case 'D':
			s.lineFeed()
			s.state = vtGround
		case 'E':
			s.cx = 0
			s.lineFeed()
			s.state = vtGround
		case 'c': // full reset
			s.eraseDisplay(2)
			s.cx, s.cy, s.state = 0, 0, vtGround
		default:
			if c >= 0x20 && c <= 0x2f {
				s.state = vtEscInter
			} else {
				s.state = vtGround
			}
		}
		return
	case vtEscInter:
		if c < 0x20 || c > 0x2f {
			s.state = vtGround
		}
		return
	case vtCSI:
		if c >= 0x40 && c <= 0x7e {
			s.csi(c)
			s.state = vtGround
		} else if len(s.params) < 64 {
			s.params = append(s.params, c)
		}
		return
	case vtOSC:
		switch c {
		case 0x07:
			s.endOSC(off + 1)
		case 0x1b:
			s.state = vtOSCEsc
		default:
			if len(s.osc) < 8192 {
				s.osc = append(s.osc, c)
			}
		}
		return
	case vtOSCEsc:
		if c == '\\' {
			s.endOSC(off + 1)
			return
		}
		s.state = vtGround
		s.byte1(0x1b, off-1, now) // not ST: treat as a new escape
		s.byte1(c, off, now)
		return
	}
	// ground
	if len(s.utf) > 0 || c >= 0x80 {
		if len(s.utf) == 0 {
			s.utfStart = off
		}
		s.utf = append(s.utf, c)
		if utf8.FullRune(s.utf) {
			r, _ := utf8.DecodeRune(s.utf)
			s.utf = s.utf[:0]
			s.put(r, s.utfStart, off+1, now)
		} else if len(s.utf) >= 4 {
			s.utf = s.utf[:0]
			s.put(utf8.RuneError, s.utfStart, off+1, now)
		}
		return
	}
	switch c {
	case 0x1b:
		s.state = vtEsc
	case '\r':
		s.cx, s.wrap = 0, false
	case '\n', 0x0b, 0x0c:
		s.wrap = false
		s.lineFeed()
	case 0x08:
		if s.cx > 0 {
			s.cx--
		}
		s.wrap = false
	case '\t':
		s.cx = clamp((s.cx/8+1)*8, 0, s.w-1)
	default:
		if c >= 0x20 && c != 0x7f {
			s.put(rune(c), off, off+1, now)
		}
	}
}

func (s *vtScreen) endOSC(end int64) {
	s.state = vtGround
	if s.onOSC != nil {
		s.onOSC(string(s.osc), s.oscStart, end)
	}
}

func runeWidth(r rune) int {
	switch {
	case r == 0:
		return 0
	case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == 0x200B:
		return 0
	case r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) || (r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe30 && r <= 0xfe4f) || (r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1f64f) || (r >= 0x1f900 && r <= 0x1f9ff) ||
		(r >= 0x20000 && r <= 0x3fffd)):
		return 2
	}
	return 1
}

// put writes one rune at the cursor with autowrap.
func (s *vtScreen) put(r rune, start, end int64, now int64) {
	wd := runeWidth(r)
	if wd == 0 { // combining: attach to the previous cell
		x := s.cx - 1
		if s.wrap {
			x = s.cx
		}
		if x >= 0 {
			s.rows[s.cy].cells[x] += string(r)
			s.touch(s.rows[s.cy], start, end, now)
		}
		return
	}
	wrapped := false
	if s.wrap || s.cx+wd > s.w {
		s.cx = 0
		s.lineFeed()
		s.rows[s.cy].cont = true
		s.link(s.cy)
		s.wrap = false
		wrapped = true
	}
	row := s.rows[s.cy]
	if s.cx == 0 && !wrapped {
		// Codex 04E (native trace native-cmd-codex-04d): text painted from
		// column 0 after CR/LF or cursor positioning — not by autowrap — is a
		// new logical line, whatever the row showed before. ConPTY repaints
		// the whole screen in place after a resize (CUP/CRLF + text + EL, no
		// clear), and with a different width the rows shift: without this
		// the repainted prompt kept the identity (and decisions) of the line
		// that row used to hold, and the next command was lost.
		row.cont = false
		if row.line != nil {
			s.dropRow(row, false) // the old line keeps the text it had
		}
	}
	row.cells[s.cx] = string(r)
	if wd == 2 && s.cx+1 < s.w {
		row.cells[s.cx+1] = "\x00"
	}
	if row.line == nil {
		s.link(s.cy)
	}
	s.touch(row, start, end, now)
	if s.cx+wd >= s.w {
		s.cx = s.w - 1
		s.wrap = true
	} else {
		s.cx += wd
	}
}

// link attaches row y to the logical line of the previous row (autowrap
// continuation) or to a new logical line.
func (s *vtScreen) link(y int) {
	row := s.rows[y]
	if row.cont && y > 0 && s.rows[y-1].line != nil {
		l := s.rows[y-1].line
		if row.line != l {
			if old := row.line; old != nil { // the row is reused: detach it
				for k, r := range old.rows {
					if r == row {
						old.rows = append(old.rows[:k:k], old.rows[k+1:]...)
						break
					}
				}
			}
			row.line = l
			l.rows = append(l.rows, row)
		}
		return
	}
	if row.line == nil {
		row.line = &vtLine{rows: []*vtRow{row}, firstOff: -1}
	}
}

func (s *vtScreen) touch(row *vtRow, start, end, now int64) {
	l := row.line
	if l == nil {
		return
	}
	if s.noOffsets {
		if s.onWrite != nil {
			s.onWrite(l, -1, -1)
		}
		return
	}
	if l.firstOff < 0 {
		l.firstOff, l.firstAt = start, now
	}
	if end > l.lastEnd {
		l.lastEnd = end
	}
	if s.onWrite != nil {
		s.onWrite(l, start, end)
	}
}

func (s *vtScreen) lineFeed() {
	if s.cy == s.bot {
		s.scrollUp(1)
	} else if s.cy < s.h-1 {
		s.cy++
	}
}

func (s *vtScreen) scrollUp(n int) {
	for ; n > 0; n-- {
		gone := s.rows[s.top]
		copy(s.rows[s.top:s.bot], s.rows[s.top+1:s.bot+1])
		s.rows[s.bot] = s.newRow()
		s.dropRow(gone, true)
	}
}

func (s *vtScreen) scrollDown(n int) {
	for ; n > 0; n-- {
		gone := s.rows[s.bot]
		copy(s.rows[s.top+1:s.bot+1], s.rows[s.top:s.bot])
		s.rows[s.top] = s.newRow()
		s.dropRow(gone, false)
	}
}

// dropRow: a row leaves the screen. It is detached from its logical line:
// a first row's text moves into the line's bounded head, any other row's
// text is dropped and the line marked cut. No reference to the row remains,
// so the model never holds more than the screen plus maxLineText per line.
func (s *vtScreen) dropRow(r *vtRow, scrolledOff bool) {
	l := r.line
	r.line = nil
	if l == nil {
		if scrolledOff && s.onScrollOff != nil {
			s.onScrollOff("", true)
		}
		return
	}
	k := -1
	for i, x := range l.rows {
		if x == r {
			k = i
			break
		}
	}
	if k < 0 {
		return
	}
	if k == 0 && !l.cut {
		t := rowText(r.cells, len(l.rows) == 1)
		if room := maxLineText - len(l.head); len(t) > room {
			l.head += truncUTF8(t, room)
			l.cut = true
		} else {
			l.head += t
		}
	} else if k > 0 && rowText(r.cells, true) != "" {
		l.cut = true
	}
	l.rows[k] = nil
	l.rows = append(l.rows[:k:k], l.rows[k+1:]...) // fresh array: no stale pointer
	if scrolledOff && s.onScrollOff != nil {
		if len(l.rows) == 0 {
			s.onScrollOff(l.text(), true)
		} else {
			s.onScrollOff("", false)
		}
	}
}

// rowText renders one row's cells (blanks as spaces); trim drops trailing
// blanks (the row is the last of its line).
func rowText(cells []string, trim bool) string {
	var b strings.Builder
	for _, c := range cells {
		switch c {
		case "":
			b.WriteByte(' ')
		case "\x00":
		default:
			b.WriteString(c)
		}
	}
	if trim {
		return strings.TrimRight(b.String(), " ")
	}
	return b.String()
}

func truncUTF8(t string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(t) <= n {
		return t
	}
	for n > 0 && !utf8.RuneStart(t[n]) {
		n--
	}
	return t[:n]
}

func (s *vtScreen) clearRow(y int) {
	old := s.rows[y]
	s.rows[y] = s.newRow()
	s.dropRow(old, false)
}

func (s *vtScreen) eraseDisplay(mode int) {
	switch mode {
	case 0:
		s.eraseLine(0)
		for y := s.cy + 1; y < s.h; y++ {
			s.clearRow(y)
		}
	case 1:
		s.eraseLine(1)
		for y := 0; y < s.cy; y++ {
			s.clearRow(y)
		}
	case 2, 3:
		for y := 0; y < s.h; y++ {
			s.clearRow(y)
		}
	}
}

func (s *vtScreen) eraseLine(mode int) {
	row := s.rows[s.cy]
	lo, hi := 0, s.w
	switch mode {
	case 0:
		lo = s.cx
	case 1:
		hi = s.cx + 1
	}
	for x := lo; x < hi && x < s.w; x++ {
		row.cells[x] = ""
	}
}

func (s *vtScreen) csi(final byte) {
	p := string(s.params)
	private := strings.HasPrefix(p, "?") || strings.HasPrefix(p, ">") || strings.HasPrefix(p, "=")
	if private {
		return // modes (cursor visibility, focus, win32-input...): no screen effect
	}
	args := []int{}
	for _, f := range strings.Split(p, ";") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			n = 0
		}
		args = append(args, n)
	}
	arg := func(i, def int) int {
		if i < len(args) && args[i] > 0 {
			return args[i]
		}
		return def
	}
	s.wrap = false
	switch final {
	case 'H', 'f':
		s.cy, s.cx = clamp(arg(0, 1)-1, 0, s.h-1), clamp(arg(1, 1)-1, 0, s.w-1)
	case 'A':
		s.cy = clamp(s.cy-arg(0, 1), 0, s.h-1)
	case 'B', 'e':
		s.cy = clamp(s.cy+arg(0, 1), 0, s.h-1)
	case 'C', 'a':
		s.cx = clamp(s.cx+arg(0, 1), 0, s.w-1)
	case 'D':
		s.cx = clamp(s.cx-arg(0, 1), 0, s.w-1)
	case 'E':
		s.cy, s.cx = clamp(s.cy+arg(0, 1), 0, s.h-1), 0
	case 'F':
		s.cy, s.cx = clamp(s.cy-arg(0, 1), 0, s.h-1), 0
	case 'G', '`':
		s.cx = clamp(arg(0, 1)-1, 0, s.w-1)
	case 'd':
		s.cy = clamp(arg(0, 1)-1, 0, s.h-1)
	case 'J':
		s.eraseDisplay(arg(0, 0))
	case 'K':
		s.eraseLine(arg(0, 0))
	case 'X':
		row := s.rows[s.cy]
		for x := s.cx; x < s.cx+arg(0, 1) && x < s.w; x++ {
			row.cells[x] = ""
		}
	case '@':
		row := s.rows[s.cy]
		n := arg(0, 1)
		copy(row.cells[min(s.cx+n, s.w):], row.cells[s.cx:])
		for x := s.cx; x < s.cx+n && x < s.w; x++ {
			row.cells[x] = ""
		}
	case 'P':
		row := s.rows[s.cy]
		n := arg(0, 1)
		if s.cx+n < s.w {
			copy(row.cells[s.cx:], row.cells[s.cx+n:])
		}
		for x := max(s.w-n, s.cx); x < s.w; x++ {
			row.cells[x] = ""
		}
	case 'S':
		s.scrollUp(arg(0, 1))
	case 'T':
		s.scrollDown(arg(0, 1))
	case 'L':
		if s.cy >= s.top && s.cy <= s.bot {
			t := s.top
			s.top = s.cy
			s.scrollDown(arg(0, 1))
			s.top = t
		}
	case 'M':
		if s.cy >= s.top && s.cy <= s.bot {
			t := s.top
			s.top = s.cy
			s.scrollUp(arg(0, 1))
			s.top = t
		}
	case 'r':
		t, b := arg(0, 1)-1, arg(1, s.h)-1
		if t < b && b < s.h {
			s.top, s.bot = t, b
		} else {
			s.top, s.bot = 0, s.h-1
		}
		s.cx, s.cy = 0, 0
	}
}

// text returns the logical line as a terminal shows it: every row but the
// last contributes all its cells (it wrapped), blanks are spaces, trailing
// blanks are trimmed.
func (l *vtLine) text() string {
	var b strings.Builder
	b.WriteString(l.head)
	for i, r := range l.rows {
		row := r.cells
		if i == len(l.rows)-1 {
			n := len(row)
			for n > 0 && row[n-1] == "" {
				n--
			}
			row = row[:n]
		}
		for _, c := range row {
			switch c {
			case "":
				b.WriteByte(' ')
			case "\x00":
			default:
				b.WriteString(c)
			}
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// followsAtColumn0: next's first row is the screen row right after prev's
// last row, and next has text in column 0 (Codex 04I, wrapped echo).
func (s *vtScreen) followsAtColumn0(prev, next *vtLine) bool {
	if len(prev.rows) == 0 || len(next.rows) == 0 {
		return false
	}
	last, first := prev.rows[len(prev.rows)-1], next.rows[0]
	for y := 0; y+1 < len(s.rows); y++ {
		if s.rows[y] == last {
			return s.rows[y+1] == first && first.cells[0] != ""
		}
	}
	return false
}
