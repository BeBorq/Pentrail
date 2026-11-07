package capture

import (
	"crypto/subtle"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BeBorq/Pentrail/internal/store"
)

// cmdSegmenter is the platform-independent core of the CMD observer. cmd.exe
// has no pre-exec hook: command text comes from what cmd echoed after its
// prompt, command boundaries from where the prompt appears on screen.
//
// Codex iteration 04B (native ConPTY traces in testdata/native-cmd-codex-04a):
// ConPTY passes the prompt marker (an OSC string) through the moment cmd
// writes it, but paints text in later frames. The marker therefore usually
// arrives BEFORE the output of the command it ends, and several markers can
// arrive together before one frame with several prompts. Byte position of a
// marker is not a screen position. So:
//
//   - The output stream is decoded like a terminal (vtScreen). "A" markers
//     only COUNT prompts; from 0.6.4 a "P" marker right after "A" carries
//     the prompt's visible text (capture.CMDPrompt).
//   - A prompt is the logical screen line that starts with the prompt text
//     (marker payload; for markers without payload the default "$P$G" shape
//     "X:\path>"), while a marker is pending. Its first write ends the
//     previous command's output range.
//   - Codex 04C: output can LOOK like the prompt (a file, a remote target's
//     text, a log with "C:\path>" lines), and because of the order above it
//     is painted while the next prompt's marker is pending. Such a line is
//     only a CANDIDATE: the running command is closed at it provisionally,
//     and a later candidate for the same marker supersedes it (the end
//     moves on to the later line). A candidate is confirmed by a command
//     echo with Enter evidence after it, or by a second marker announced
//     after it was painted (the prompt took no command: empty Enter,
//     Ctrl-C). A line wholly painted before its marker cannot be the prompt
//     the marker announces (cmd writes marker and prompt text together, the
//     text after the marker). Only a confirmed prompt starts a command.
//   - The command is the rest of that line as cmd echoed it, taken when the
//     line is finished (the next write lands on another line). It is recorded
//     only with evidence that Enter was pressed for it: a typed line with the
//     same text (exact typed text is kept), or an edited/recalled typed line
//     (history, Tab: the echoed text is what cmd ran). Its output range starts
//     after the echo.
//   - Lines typed while a program runs (set /p, prompts of tools) are echoed
//     on the program's line, never after a cmd prompt: never commands; they
//     are counted as unattributed when a later command shows they were
//     consumed, or at the end.
//   - LF is not Enter for cmd under ConPTY (native trace: "echo X\n" waited
//     for CR); only CR ends a typed line, LF is ignored.
//   - The exit status is never known (cmd prints none): ExitCode -1,
//     Complete false.
type cmdSegmenter struct {
	token   string
	write   func(store.Command)
	note    func(int64) // unattributed lines
	id      int64
	index   int64
	now     func() int64
	scr     *vtScreen
	pending []promptMark
	cur     *vtLine
	running *store.Command

	// tent: the current, not yet confirmed prompt candidate for pending[0];
	// prov: the command closed provisionally at tent (its end moves on if a
	// later candidate supersedes tent).
	tent      *vtLine
	prov      *store.Command
	wrap      *wrapHold // tent echo possibly continued on the next row
	provDirty bool      // prov's end changed and is not written yet
	// lastOff: offset after the last recorded output byte; resizeOff: lastOff
	// at the last resize (-1: none) — a repaint follows a resize.
	lastOff, resizeOff int64
	feedAt             int64 // time of the output being processed

	// dbg (diagnostics only, nil in production): one line per decision.
	dbg func(format string, args ...any)

	recording bool
	line      []byte
	bad       bool
	queue     []typedLine
}

// segLine is the segmenter's state of one logical screen line.
type segLine struct {
	decided, prompt, closed bool
	promptLen               int
}

// wrapHold (Codex 04I): the candidate prompt line filled its last column
// with an echo the typed input did not confirm; ConPTY may continue a
// wrapped echo on the next row at column 0 (after a cursor position or
// CRLF), which the screen model takes for a new line. The next line — if it
// starts at column 0 of the following row — is joined to the echo, and the
// command is confirmed only if the typed input confirms the joined text.
type wrapHold struct {
	tent *vtLine
	text string  // echo so far (after the prompt)
	last *vtLine // the line whose last row is full
	next *vtLine // the line painted at column 0 of the following row
}

type promptMark struct {
	text string
	has  bool
	off  int64 // raw offset just after the "A" marker; -1: received while paused
}

type typedLine struct {
	text []byte
	bad  bool
}

const (
	maxQueuedLines = 64
	maxLineBytes   = 8192
	maxPending     = 64
	// maxPromptText: a line longer than this without the prompt shape is
	// decided not to be a prompt at once (bounds work on long output lines).
	maxPromptText = 8192
	// ConPTY's initial size (pty_windows.go); resizes are passed on.
	cmdCols, cmdRows = 120, 30
)

// defaultPrompt is the visible shape of cmd's default "$P$G" prompt:
// a drive or UNC path followed by '>' (a path cannot contain '>').
var defaultPrompt = regexp.MustCompile(`^(?:[A-Za-z]:\\|\\\\[^\\<>|"*?]+\\)[^<>|"*?\r\n]*>`)

// couldBePrompt: t is a prefix of something of the default prompt's shape.
func couldBePrompt(t string) bool {
	switch {
	case t == "":
		return true
	case len(t) == 1:
		return (t[0]|0x20 >= 'a' && t[0]|0x20 <= 'z') || t[0] == '\\'
	case t[0] == '\\':
		return t[1] == '\\' && !strings.ContainsAny(t[2:], `<>|"*?`)
	case len(t) == 2:
		return defaultPrompt.MatchString(t + `\>`)
	}
	return defaultPrompt.MatchString(t + ">")
}

func newCmdSegmenter(token string, id int64, write func(store.Command), note func(int64)) *cmdSegmenter {
	c := &cmdSegmenter{token: token, id: id, write: write, note: note, now: func() int64 { return time.Now().UnixNano() }, resizeOff: -1}
	c.scr = newVTScreen(cmdCols, cmdRows)
	c.scr.onOSC = c.onOSC
	c.scr.onWrite = c.onWrite
	return c
}

// Resize follows the console size (the client's window). ConPTY repaints
// the screen after it; the repaint is recognised by resizeOff.
func (c *cmdSegmenter) Resize(cols, rows int) {
	c.scr.resize(cols, rows)
	c.resizeOff = c.lastOff
	c.debug("resize %dx%d at %d; pending=%d tent=%s", cols, rows, c.lastOff, len(c.pending), c.lineInfo(c.tent))
}

func (c *cmdSegmenter) debug(format string, args ...any) {
	if c.dbg != nil {
		c.dbg(format, args...)
	}
}

// lineInfo (diagnostics only): offsets and text of l.
func (c *cmdSegmenter) lineInfo(l *vtLine) string {
	if l == nil || c.dbg == nil {
		return "-"
	}
	t := l.text()
	if len(t) > 160 {
		t = t[:160] + "…"
	}
	return fmt.Sprintf("[%d..%d rows=%d cut=%v %q]", l.firstOff, l.lastEnd, len(l.rows), l.cut, t)
}

func (c *cmdSegmenter) onOSC(payload string, start, end int64) {
	const pfx = "697;"
	if !strings.HasPrefix(payload, pfx) {
		return
	}
	rest := payload[len(pfx):]
	semi := strings.IndexByte(rest, ';')
	if semi < 0 || subtle.ConstantTimeCompare([]byte(rest[:semi]), []byte(c.token)) != 1 {
		return
	}
	rest = rest[semi+1:]
	verb, arg := rest, ""
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		verb, arg = rest[:i], rest[i+1:]
	}
	// counted also while paused: screen state, not attribution (a prompt
	// painted during a pause takes the first command typed after resuming)
	switch verb {
	case "A":
		if len(c.pending) >= maxPending {
			c.pending = c.pending[1:]
			c.tent = nil // its marker is gone
		}
		m := promptMark{off: end}
		if c.scr.noOffsets {
			m.off = -1
		}
		c.pending = append(c.pending, m)
	case "P": // the visible text of the prompt just announced by "A"
		if n := len(c.pending); n > 0 && !c.pending[n-1].has && strings.TrimRight(arg, " ") != "" {
			c.pending[n-1].text, c.pending[n-1].has = strings.TrimRight(arg, " "), true
		}
	}
}

func (c *cmdSegmenter) onWrite(l *vtLine, start, end int64) {
	if l == c.cur {
		return
	}
	if c.cur != nil {
		c.closeLine(c.cur)
	}
	if w := c.wrap; w != nil && w.next == nil {
		if c.cur == w.last && c.scr.followsAtColumn0(w.last, l) {
			w.next = l
		} else {
			c.wrap = nil
		}
	}
	c.cur = l
	l.seg.closed = false // written again: closed again when left
}

// matchPrompt: the prompt length if l shows the prompt of m, -1 if not;
// wait while l is still being painted and could still become it.
func matchPrompt(t string, m promptMark, final bool) (plen int, wait bool) {
	if m.has {
		switch {
		case strings.HasPrefix(t, m.text):
			return len(m.text), false
		case !final && strings.HasPrefix(m.text, t):
			return -1, true
		}
		return -1, false
	}
	if i := strings.IndexByte(t, '>'); i >= 0 && i < maxPromptText {
		if defaultPrompt.MatchString(t[:i+1]) {
			return i + 1, false
		}
		return -1, false
	}
	if !final && len(t) <= maxPromptText && couldBePrompt(t) {
		return -1, true
	}
	return -1, false
}

// checkPrompt decides whether l is a candidate for the oldest pending
// prompt. It may be undecided while the line is still being painted.
func (c *cmdSegmenter) checkPrompt(l *vtLine, final bool) {
	if l == nil || l.seg.decided || len(c.pending) == 0 {
		return
	}
	m := c.pending[0]
	// painted wholly before the marker: not the prompt it announces (it may
	// still become one if written again after it)
	if m.off >= 0 && l.firstOff >= 0 && l.lastEnd <= m.off {
		return
	}
	plen, wait := matchPrompt(l.text(), m, final)
	if wait {
		return
	}
	l.seg.decided = true
	if plen < 0 {
		return
	}
	c.debug("candidate %s plen=%d pending=%d tent=%s", c.lineInfo(l), plen, len(c.pending), c.lineInfo(c.tent))
	if c.tent != nil && c.tent != l {
		if c.answered(c.tent, l) {
			c.debug("  tent answered (marker after it): confirmed without command")
			// tent was a real prompt that took no command: its marker is
			// used up, l is matched against the next one
			c.confirm()
			l.seg.decided = false
			c.checkPrompt(l, final)
			return
		}
		if c.repaintOf(l) {
			c.debug("  repaint after resize: tent moves, end stays")
			// the screen was repainted after a resize: the latest painted
			// candidate is tent, the provisional end stays where it is
			c.tent.seg.prompt = false
			l.seg.prompt, l.seg.promptLen = true, plen
			c.tent = l
			return
		}
		// tent was output that looked like the prompt: superseded
		c.debug("  tent superseded")
		c.tent.seg.prompt = false
	}
	l.seg.prompt, l.seg.promptLen = true, plen
	c.tent = l
	c.wrap = nil
	// the candidate's first write ends the running command's output
	// (provisionally: a later candidate for the same marker moves it on)
	if c.running != nil {
		c.prov, c.running = c.running, nil
	}
	if c.prov != nil {
		c.prov.EndedAt = l.firstAt
		if c.prov.EndedAt == 0 {
			c.prov.EndedAt = c.now()
		}
		c.prov.OutEndOff = max(l.firstOff, c.prov.OutStartOff) // firstOff -1: painted while paused
		c.provDirty = true                                     // written once per output chunk (many prompt-like lines cost one write)
	}
}

// flushProv writes the provisional end if it changed.
func (c *cmdSegmenter) flushProv() {
	if c.prov != nil && c.provDirty {
		c.emit(*c.prov)
	}
	c.provDirty = false
}

// answered: a further prompt was announced after tent was painted and
// before l: cmd printed a new prompt after tent, so tent was a real prompt
// that took no command. Output imitating the prompt is painted in the same
// frame as the real prompt, with no marker in between (markers of later
// prompts can only follow input given at the real one). Unknown offsets
// (paused) count as answered, as before 04C.
func (c *cmdSegmenter) answered(tent, l *vtLine) bool {
	if len(c.pending) < 2 {
		return false
	}
	m := c.pending[1].off
	if m < 0 || tent.firstOff < 0 || l.firstOff < 0 {
		return true
	}
	return m > tent.firstOff && m <= l.firstOff
}

// repaintOf: l is painted by the repaint that follows a resize, and the
// provisional end was set before that resize: the repaint shows again what
// was already on screen (old prompt-like lines included) and must not move
// that end.
func (c *cmdSegmenter) repaintOf(l *vtLine) bool {
	return c.resizeOff >= 0 && l.firstOff >= c.resizeOff &&
		(c.prov == nil || c.prov.OutEndOff <= c.resizeOff)
}

// confirm: tent is the prompt pending[0] announced.
func (c *cmdSegmenter) confirm() {
	c.wrap = nil
	c.flushProv()
	c.pending = c.pending[1:]
	c.tent, c.prov = nil, nil
}

// closeLine: the line is finished (the next write went elsewhere, or EOF).
func (c *cmdSegmenter) closeLine(l *vtLine) {
	if l.seg.closed {
		return
	}
	l.seg.closed = true
	c.checkPrompt(l, true)
	if w := c.wrap; w != nil && w.next == l {
		c.closeWrapped(w, l)
		return
	}
	// Only the current candidate can take a command. Attribution needs
	// recording NOW and Enter typed while recording (the queue is cleared at
	// every off/on): input of a paused period is never attributed.
	if !l.seg.prompt || l != c.tent || !c.recording || l.cut {
		if c.dbg != nil && (l.seg.prompt || len(c.queue) > 0) {
			c.debug("close %s: no command (prompt=%v tent=%v recording=%v cut=%v queue=%d)", c.lineInfo(l), l.seg.prompt, l == c.tent, c.recording, l.cut, len(c.queue))
		}
		return // a cut line's echo may be incomplete: never a command
	}
	t := l.text()
	if l.seg.promptLen > len(t) {
		return
	}
	rest := strings.TrimSpace(t[l.seg.promptLen:])
	if rest == "" {
		return // Enter on an empty line, or not yet answered: stays a candidate
	}
	text, ok := c.takeTyped(rest)
	if !ok {
		c.debug("close %s: echo %q has no Enter evidence (queue=%d)", c.lineInfo(l), rest, len(c.queue))
		if lastColumnFull(l) && len(c.queue) > 0 {
			c.wrap = &wrapHold{tent: l, text: rest, last: l}
		}
		return // echoed text without Enter evidence: not a command
	}
	c.debug("close %s: command %q", c.lineInfo(l), text)
	c.startCommand(text, l.lastEnd)
}

// closeWrapped: l continued the held echo at column 0 of the next row.
func (c *cmdSegmenter) closeWrapped(w *wrapHold, l *vtLine) {
	c.wrap = nil
	if w.tent != c.tent || !c.recording || l.cut {
		return
	}
	joined := w.text + l.text()
	echo := strings.TrimSpace(joined)
	if text, ok := c.takeTyped(echo); ok {
		c.debug("close %s: wrapped echo continued at column 0, command %q", c.lineInfo(l), text)
		c.startCommand(text, l.lastEnd)
		return
	}
	if lastColumnFull(l) && len(c.queue) > 0 { // a third row?
		c.wrap = &wrapHold{tent: w.tent, text: joined, last: l}
	}
}

// startCommand: the candidate prompt is confirmed by the echo of text;
// its output starts at off.
func (c *cmdSegmenter) startCommand(text string, off int64) {
	c.confirm()
	cmd := store.Command{SessionID: c.id, Index: c.index, Command: text, StartedAt: c.feedAt,
		OutStartOff: off, ExitCode: -1}
	if cmd.StartedAt == 0 {
		cmd.StartedAt = c.now()
	}
	c.index++
	c.running = &cmd
	c.emit(cmd)
}

// takeTyped finds the typed line cmd echoed. Lines typed before it that
// were not echoed after a prompt were consumed by programs: unattributed.
func (c *cmdSegmenter) takeTyped(echo string) (string, bool) {
	for k, q := range c.queue {
		if !q.bad && strings.TrimSpace(string(q.text)) == echo {
			c.unattributed(int64(k))
			c.queue = c.queue[k+1:]
			return string(q.text), true
		}
	}
	// history recall / Tab / editing: the typed bytes do not show the text,
	// the echo after the prompt does
	if len(c.queue) > 0 && c.queue[0].bad {
		c.queue = c.queue[1:]
		return echo, true
	}
	return "", false
}

func (c *cmdSegmenter) emit(cmd store.Command) {
	if c.write != nil {
		c.write(cmd)
	}
}

func (c *cmdSegmenter) unattributed(n int64) {
	if n > 0 && c.note != nil && c.recording {
		c.note(n)
	}
}

// Input receives decoded keystroke bytes (UTF-8).
func (c *cmdSegmenter) Input(b []byte, off int64, recording bool) {
	c.recording = recording
	for _, v := range b {
		switch v {
		case '\n':
			// not Enter for cmd under ConPTY; nothing is inserted either
		case '\r':
			c.endLine()
		case 8, 127:
			if len(c.line) > 0 {
				_, n := utf8.DecodeLastRune(c.line)
				c.line = c.line[:len(c.line)-n]
			}
		default:
			if v < 32 {
				c.bad = true // escape sequences (arrows, history), Tab, Ctrl-keys
			}
			if len(c.line) < maxLineBytes {
				c.line = append(c.line, v)
			} else {
				c.bad = true
			}
		}
	}
}

func (c *cmdSegmenter) endLine() {
	text, bad := c.line, c.bad
	c.line, c.bad = nil, false
	if !c.recording || (len(text) == 0 && !bad) {
		return
	}
	if len(c.queue) >= maxQueuedLines {
		c.queue = c.queue[1:]
		c.unattributed(1)
	}
	c.queue = append(c.queue, typedLine{text: text, bad: bad})
}

// Output receives terminal output, whose first byte is at offset off.
func (c *cmdSegmenter) Output(b []byte, off int64, recording bool) {
	c.recording = recording
	c.scr.noOffsets = !recording // paused bytes are not in the recorded stream
	c.feedAt = c.now()
	c.scr.Feed(b, off, c.feedAt)
	if recording {
		c.lastOff = off + int64(len(b))
	}
	c.checkPrompt(c.cur, false)
	c.flushProv()
}

// Reset is a recording boundary (off/on): input from a paused period must
// never be attributed to a recorded command. A command still running when
// recording is paused keeps the output recorded so far: it is closed at off
// with the reason, its exit status unknown.
func (c *cmdSegmenter) Reset(off int64) {
	c.closeRunning(off, store.EndRecordingPaused)
	c.wrap = nil // the queue is cleared: nothing could confirm it
	c.flushProv()
	c.prov = nil // a provisional end stands across a pause
	c.unattributed(int64(len(c.queue)))
	c.line, c.bad, c.queue = nil, false, nil
}

// Close is called once at EOF. A line still open (e.g. "exit" echoed after
// the last prompt) is finished first. The running command's end was not
// observed: it is closed at the end of the captured output, exit status
// unknown. Typed lines never echoed after a prompt are unattributed.
func (c *cmdSegmenter) Close(off int64) {
	if c.cur != nil {
		c.closeLine(c.cur)
		c.cur = nil
	}
	c.flushProv()
	c.closeRunning(off, store.EndSessionEnded)
	c.unattributed(int64(len(c.queue)))
	c.line, c.bad, c.queue, c.pending = nil, false, nil, nil
	c.tent, c.prov = nil, nil // a provisional end stands: no later prompt was painted
}

func (c *cmdSegmenter) closeRunning(off int64, reason string) {
	if c.running == nil || !c.recording {
		c.running = nil
		return
	}
	r := c.running
	c.running = nil
	r.EndedAt = c.now()
	r.OutEndOff = max(off, r.OutStartOff)
	r.ExitCode = -1
	r.Complete = false
	r.EndReason = reason
	c.emit(*r)
}

// lastColumnFull: the line's last row has text in its last column (a
// wrapped echo would continue on the next row).
func lastColumnFull(l *vtLine) bool {
	if len(l.rows) == 0 {
		return false
	}
	r := l.rows[len(l.rows)-1]
	return len(r.cells) > 0 && r.cells[len(r.cells)-1] != ""
}
