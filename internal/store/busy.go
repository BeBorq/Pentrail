package store

import (
	"fmt"
	"os"
	"time"
)

// busyRetryWindow bounds how long a durable capture write keeps retrying while
// ANOTHER process (pentrail serve/open/report/extract, a backup, a second
// session) holds the database write lock. SQLite already waits busy_timeout
// (5 s) inside each attempt; this loop adds bounded retries on top.
//
// Without it, one lock held for more than 5 s made a capture write fail, the
// failure was recorded as a sticky write error, every later write failed even
// after the lock was released, and the session server killed the user's shell.
// A lock is contention, not data loss: the right reaction is the same as a slow
// disk — the terminal output pauses (the PTY applies normal flow control to the
// shell) and resumes when the lock is released. Only a lock held for the whole
// window, or any non-lock error, is treated as a definitive capture failure.
var busyRetryWindow = 2 * time.Minute

// retryBusy runs op until it succeeds, fails with a non-lock error, or the
// lock-contention window is exhausted. op must be safe to repeat: every caller
// rebuilds its state from scratch on each attempt (failed attempts roll back).
func retryBusy(what string, op func() error) error {
	start := time.Now()
	backoff := 100 * time.Millisecond
	warned := false
	for {
		err := op()
		if err == nil {
			if warned {
				fmt.Fprintf(os.Stderr, "pentrail: database lock released; %s resumed after %v\n", what, time.Since(start).Round(time.Millisecond))
			}
			return nil
		}
		if !isBusy(err) || time.Since(start) >= busyRetryWindow {
			return err
		}
		if !warned {
			fmt.Fprintf(os.Stderr, "pentrail: database is locked by another process; %s is waiting (terminal output pauses, nothing is dropped): %v\n", what, err)
			warned = true
		}
		time.Sleep(backoff)
		if backoff < time.Second {
			backoff *= 2
		}
	}
}
