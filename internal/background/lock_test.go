//go:build linux

package background

import (
	"testing"
	"time"
)

func TestControlLockSerializesStartupAndOff(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release, err := Lock()
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		unlock, e := Lock()
		if e == nil {
			unlock()
		}
		acquired <- e
	}()
	<-started
	select {
	case e := <-acquired:
		release()
		t.Fatalf("second operation escaped lock: %v", e)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case e := <-acquired:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("lock did not release")
	}
}
