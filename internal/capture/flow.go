package capture

import "time"

// Codex 04D: per-stage timing of the session's output path (PTY read →
// segmenter/observer → OSC parser → durable store write → client hub), for
// diagnostic tests only. flowHook is nil in production; then no clock is
// read and nothing is recorded.

// FlowSample describes one PTY read and its trip through the output path.
type FlowSample struct {
	Session int64            // the session (several can run in one test process)
	N       int              // bytes read from the PTY (one batch)
	Offset  int64            // recorded offset after it (unchanged while paused)
	Stage   [5]time.Duration // see flowStages
	Held    time.Duration    // how long the session's capture lock was held for it
}

// flowStages names FlowSample.Stage entries.
var flowStages = [5]string{"pty-read-wait", "observer", "parser", "store", "hub-publish"}

const (
	flowRead = iota
	flowObserver
	flowParser
	flowStore
	flowPublish
)

// flowHook: set by diagnostic tests before RunServer starts.
var flowHook func(FlowSample)

type flowTimer struct {
	s        FlowSample
	last     time.Time
	lockedAt time.Time
}

// startFlow returns nil (all methods no-ops) unless a test set flowHook.
func startFlow() *flowTimer {
	if flowHook == nil {
		return nil
	}
	return &flowTimer{last: time.Now()}
}

// lap charges the time since the previous lap to stage.
func (f *flowTimer) lap(stage int) {
	if f == nil {
		return
	}
	now := time.Now()
	f.s.Stage[stage] += now.Sub(f.last)
	f.last = now
}

func (f *flowTimer) locked() {
	if f != nil {
		f.lockedAt = time.Now()
	}
}

func (f *flowTimer) unlocked() {
	if f != nil {
		f.s.Held = time.Since(f.lockedAt)
	}
}

func (f *flowTimer) done(session int64, n int, offset int64) {
	if f == nil {
		return
	}
	f.s.Session, f.s.N, f.s.Offset = session, n, offset
	if h := flowHook; h != nil {
		h(f.s)
	}
}

// controlLockHook (diagnostic tests only, nil in production): how long a
// control request (status/on/off/flush) waited for the session's capture
// lock — separates waiting for the lock from everything else (scheduling,
// transport) in a request's round trip (Codex 04G).
var controlLockHook func(session int64, op string, wait time.Duration)

type lockWaitTimer struct{ t0 time.Time }

func startLockWait() *lockWaitTimer {
	if controlLockHook == nil {
		return nil
	}
	return &lockWaitTimer{t0: time.Now()}
}

func (l *lockWaitTimer) done(session int64, op string) {
	if l == nil {
		return
	}
	if h := controlLockHook; h != nil {
		h(session, op, time.Since(l.t0))
	}
}
