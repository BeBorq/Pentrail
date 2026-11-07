package sessionio

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestControlDoesNotSubscribeToTerminalOutput(t *testing.T) {
	h := NewHub()
	recording := true
	h.SetControl(func(op string) (ControlState, error) {
		if op == "off" {
			recording = false
		}
		return ControlState{SessionID: 12, Recording: recording}, nil
	})
	s, c := net.Pipe()
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	go h.ServeConn(s, func(byte, []byte) error { t.Error("control reached PTY"); return nil })
	w := NewWriter(c)
	if err := w.Send(Hello, []byte(Version+" control")); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := Read(c); err != nil || typ != Hello {
		t.Fatal(typ, err)
	}
	if err := w.Send(Control, []byte("off")); err != nil {
		t.Fatal(err)
	}
	typ, b, err := Read(c)
	if err != nil || typ != ControlReply {
		t.Fatal(typ, err)
	}
	var reply controlReply
	if err = json.Unmarshal(b, &reply); err != nil || reply.State.Recording || reply.State.SessionID != 12 {
		t.Fatal(reply, err)
	}
	h.mu.Lock()
	n := len(h.peers)
	h.mu.Unlock()
	if n != 0 {
		t.Fatal("control client subscribed to output")
	}
	h.Finish(Result{})
}
