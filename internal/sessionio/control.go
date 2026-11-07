package sessionio

import (
	"encoding/json"
	"errors"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"net"
	"time"
)

type ControlState struct {
	DatabaseID string `json:"database_id"`
	RootPID    int    `json:"root_pid"`
	ConsoleID  string `json:"console_id,omitempty"`
	SessionID  int64  `json:"session_id"`
	Recording  bool   `json:"recording"`
	// CaptureError is set when recording stopped after a storage failure.
	CaptureError string `json:"capture_error,omitempty"`
}
type controlReply struct {
	State ControlState `json:"state"`
	Error string       `json:"error,omitempty"`
}

func (h *Hub) SetControl(fn func(string) (ControlState, error)) {
	h.mu.Lock()
	h.controller = fn
	h.mu.Unlock()
}
func (h *Hub) control(c net.Conn, w *Writer) {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	typ, b, err := Read(c)
	if err != nil || typ != Control {
		return
	}
	h.mu.Lock()
	fn := h.controller
	closed := h.closed
	h.mu.Unlock()
	reply := controlReply{}
	if fn == nil || closed {
		reply.Error = "session is not available"
	} else {
		reply.State, err = fn(string(b))
		if err != nil {
			reply.Error = err.Error()
		}
	}
	b, _ = json.Marshal(reply)
	_ = w.Send(ControlReply, b)
}
func RequestControl(path, op string) (ControlState, error) {
	var result controlReply
	c, err := localipc.Dial(path, time.Second)
	if err != nil {
		return result.State, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	w := NewWriter(c)
	if err = w.Send(Hello, []byte(Version+" control")); err != nil {
		return result.State, err
	}
	typ, b, err := Read(c)
	if err != nil {
		return result.State, err
	}
	if typ != Hello || string(b) != Version {
		return result.State, errors.New("incompatible session protocol")
	}
	if err = w.Send(Control, []byte(op)); err != nil {
		return result.State, err
	}
	typ, b, err = Read(c)
	if err != nil {
		return result.State, err
	}
	if typ != ControlReply {
		return result.State, errors.New("invalid control response")
	}
	if err = json.Unmarshal(b, &result); err != nil {
		return result.State, err
	}
	if result.Error != "" {
		return result.State, errors.New(result.Error)
	}
	return result.State, nil
}
