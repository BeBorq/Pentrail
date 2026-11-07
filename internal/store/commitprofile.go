package store

import (
	"context"
	"runtime/trace"
	"time"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// Codex 04E: sub-stage timing of one durable capture write (redaction step,
// transaction begin, raw insert, checkpoint build, checkpoint upsert, commit
// = the synchronous=FULL flush), for diagnostic tests only. The hook is nil
// in production: no clock is read and nothing is recorded.
type CommitProfile struct {
	Input   int // bytes fed to the redactor by this write (0: a seal/finish, no new input; Codex 04J)
	Stored  int // bytes inserted as raw (after the redactor; may lag the input)
	Retries int // attempts beyond the first (database busy)
	Stage   [6]time.Duration
	// Codex 04K, the redaction step of the last attempt: the redactor's
	// state it started from (bytes held for an unfinished line, the
	// line prefix and the 4 KiB recognition context), the bytes it
	// produced, and what the step snapshot hook returned right before and
	// right after it (nil without a hook).
	Pending, Prefix, Context, Output int
	Snap                             [2]any
}

// CommitStages names CommitProfile.Stage entries.
var CommitStages = [6]string{"redact-step", "begin", "insert-raw", "checkpoint-build", "checkpoint-upsert", "commit"}

const (
	cpStep = iota
	cpBegin
	cpInsert
	cpBuild
	cpUpsert
	cpCommit
)

var commitProfileHook func(CommitProfile)

// stepSnapHook (diagnostic tests only, with commitProfileHook): called
// right before and right after each redaction step, on the goroutine that
// runs it; its results go into CommitProfile.Snap.
var stepSnapHook func() any

// SetStepSnapHook installs (nil: removes) the step snapshot hook. Tests only.
func SetStepSnapHook(h func() any) { stepSnapHook = h }

// SetCommitProfileHook installs (nil: removes) the diagnostic hook. Tests only.
func SetCommitProfileHook(h func(CommitProfile)) { commitProfileHook = h }

type commitTimer struct {
	p      CommitProfile
	last   time.Time
	region *trace.Region
}

// stepBegin: diagnostics only (c != nil). With an execution trace running
// (a diagnostic test started it), the step is a trace region
// "pentrail-redact-step", so the trace shows exactly what its goroutine
// did meanwhile (running, waiting, GC assist, preemption).
func (c *commitTimer) stepBegin(s *redact.Stream) {
	if c == nil {
		return
	}
	c.p.Pending, c.p.Prefix, c.p.Context = s.Sizes()
	if h := stepSnapHook; h != nil {
		c.p.Snap[0] = h()
		c.last = time.Now() // the snapshot is not part of the step's time
	}
	if trace.IsEnabled() {
		c.region = trace.StartRegion(context.Background(), "pentrail-redact-step")
	}
}

func (c *commitTimer) stepEnd(output int) {
	if c == nil {
		return
	}
	if c.region != nil {
		c.region.End()
		c.region = nil
	}
	if h := stepSnapHook; h != nil {
		c.p.Snap[1] = h()
	}
	c.p.Output = output
}

func startCommitTimer() *commitTimer {
	if commitProfileHook == nil {
		return nil
	}
	return &commitTimer{last: time.Now()}
}

func (c *commitTimer) lap(stage int) {
	if c == nil {
		return
	}
	now := time.Now()
	c.p.Stage[stage] += now.Sub(c.last)
	c.last = now
}

func (c *commitTimer) reset() { // a retry: the time until now stays charged
	if c != nil {
		c.p.Retries++
		c.last = time.Now()
	}
}

func (c *commitTimer) done(input, stored int) {
	if c == nil {
		return
	}
	c.p.Input, c.p.Stored = input, stored
	if h := commitProfileHook; h != nil {
		h(c.p)
	}
}
