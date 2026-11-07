package capture

import "github.com/BeBorq/Pentrail/internal/store"

// SegTraceEvent is one call into (or out of) the CMD segmenter, recorded only
// by diagnostic tests (Codex iteration 04A). Replaying the input/output/
// reset/close events in order through a new segmenter reproduces exactly
// what the segmenter saw in the live session, independent of timing.
type SegTraceEvent struct {
	Seq int64  `json:"seq"`
	TNs int64  `json:"t_ns"` // nanoseconds since the trace started
	Ev  string `json:"ev"`   // start|input|output|reset|close|resize|write|note|seg
	Off int64  `json:"off"`  // output offset passed with the call
	Rec bool   `json:"rec"`  // recording flag passed with the call
	// Raw: bytes as the session received them (input: before Win32 key
	// record decoding; output: PTY bytes before masking).
	Raw []byte `json:"raw,omitempty"`
	// Dec: decoded keystroke bytes actually given to the segmenter (input).
	Dec  []byte         `json:"dec,omitempty"`
	Cmd  *store.Command `json:"cmd,omitempty"` // write: the row the segmenter wrote
	N    int64          `json:"n,omitempty"`   // note: unattributed lines counted
	Tok  string         `json:"token,omitempty"`
	Cols int            `json:"cols,omitempty"` // resize
	Rows int            `json:"rows,omitempty"`
	ID   int64          `json:"session_id,omitempty"`
	Note string         `json:"note,omitempty"` // seg: a segmenter decision (diagnostics)
}

// cmdTraceHook is nil in production. Diagnostic tests set it before
// starting the session; it is called with the session's capture lock held,
// i.e. in exactly the order the segmenter receives the calls.
var cmdTraceHook func(SegTraceEvent)

func traceSeg(ev SegTraceEvent) {
	if h := cmdTraceHook; h != nil {
		h(ev)
	}
}
