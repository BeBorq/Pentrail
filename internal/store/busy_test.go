package store

import (
	"errors"
	"testing"
	"time"
)

func TestRetryBusyStopsOnRealErrors(t *testing.T) {
	calls := 0
	err := retryBusy("t", func() error { calls++; return errors.New("disk I/O error") })
	if err == nil || calls != 1 {
		t.Fatalf("non-lock error must fail at once: calls=%d err=%v", calls, err)
	}
	old := busyRetryWindow
	busyRetryWindow = 300 * time.Millisecond
	defer func() { busyRetryWindow = old }()
	calls = 0
	err = retryBusy("t", func() error {
		calls++
		if calls < 3 {
			return errors.New("database is locked")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("transient lock must be retried: calls=%d err=%v", calls, err)
	}
	start := time.Now()
	err = retryBusy("t", func() error { return errors.New("database is locked") })
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("a lock held past the window must fail, bounded: err=%v after %v", err, time.Since(start))
	}
}
