//go:build windows

package capture

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BeBorq/Pentrail/internal/store"
)

// cmdObserver feeds cmd.exe keystrokes (decoded from ConPTY Win32 input
// records) and terminal output to the platform-independent cmdSegmenter.
type cmdObserver struct {
	decoder winInputDecoder
	seg     *cmdSegmenter
}

func newShellObserver(o Options) shellObserver {
	if !strings.EqualFold(filepath.Base(o.Shell), "cmd.exe") {
		return noopObserver{}
	}
	traceSeg(SegTraceEvent{Ev: "start", Tok: o.MarkerToken, ID: o.SessionID})
	write := func(cmd store.Command) {
		if cmdTraceHook != nil {
			c := cmd
			traceSeg(SegTraceEvent{Ev: "write", Cmd: &c})
		}
		o.Store.WriteCommand(cmd)
	}
	note := func(n int64) {
		traceSeg(SegTraceEvent{Ev: "note", N: n})
		o.Store.AddUnattributedInput(o.SessionID, n)
	}
	seg := newCmdSegmenter(o.MarkerToken, o.SessionID, write, note)
	if cmdTraceHook != nil { // diagnostics: the segmenter's decisions go into the trace
		seg.dbg = func(format string, args ...any) {
			traceSeg(SegTraceEvent{Ev: "seg", Note: fmt.Sprintf(format, args...)})
		}
	}
	return &cmdObserver{seg: seg}
}

// The trace calls are no-ops unless a diagnostic test set cmdTraceHook.
func (c *cmdObserver) Reset(off int64) {
	traceSeg(SegTraceEvent{Ev: "reset", Off: off})
	c.seg.Reset(off)
}
func (c *cmdObserver) Resize(cols, rows int) {
	traceSeg(SegTraceEvent{Ev: "resize", Cols: cols, Rows: rows})
	c.seg.Resize(cols, rows)
}
func (c *cmdObserver) Close(off int64) {
	traceSeg(SegTraceEvent{Ev: "close", Off: off})
	c.seg.Close(off)
}
func (c *cmdObserver) Output(b []byte, off int64, recording bool) {
	if cmdTraceHook != nil {
		traceSeg(SegTraceEvent{Ev: "output", Off: off, Rec: recording, Raw: append([]byte(nil), b...)})
	}
	c.seg.Output(b, off, recording)
}
func (c *cmdObserver) Input(b []byte, off int64, recording bool) {
	dec := c.decoder.Decode(b)
	if cmdTraceHook != nil {
		traceSeg(SegTraceEvent{Ev: "input", Off: off, Rec: recording, Raw: append([]byte(nil), b...), Dec: append([]byte(nil), dec...)})
	}
	c.seg.Input(dec, off, recording)
}
