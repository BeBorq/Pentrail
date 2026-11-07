// Package sessionio implements the versioned local session transport. It has no
// terminal or database dependencies so transport failures can be tested directly.
package sessionio

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	Data         byte = 1
	Resize       byte = 2
	Hello        byte = 3
	Output       byte = 4
	Finished     byte = 5
	Control      byte = 6
	ControlReply byte = 7
	Version           = "pentrail-session/5"
	MaxFrame          = 1 << 20
)

// Writer serializes whole frames, including short writes, across callers.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }
func (w *Writer) Send(typ byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if err := writeAll(w.w, hdr[:]); err != nil {
		w.err = err
		return err
	}
	w.err = writeAll(w.w, payload)
	return w.err
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func Read(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("oversized frame: %d", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return hdr[0], b, err
}

// Result is sent only after the session owner has flushed and closed its store.
// OutputBytes counts PTY bytes observed; CaptureError reports persistence errors.
type Result struct {
	ExitCode     int    `json:"exit_code"`
	OutputBytes  int64  `json:"output_bytes"`
	CaptureError string `json:"capture_error,omitempty"`
}

func (r Result) Err() error {
	if r.CaptureError != "" {
		return fmt.Errorf("session capture failed: %s", r.CaptureError)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("shell exited with status %d", r.ExitCode)
	}
	return nil
}

// Receive rejects disconnects without a final result: EOF never proves success.
func Receive(r io.Reader, out io.Writer) error {
	typ, b, err := Read(r)
	if err != nil {
		return fmt.Errorf("session handshake failed (old protocol or disconnected server): %w", err)
	}
	if typ != Hello || string(b) != Version {
		return errors.New("incompatible session protocol; client and server must use the same version")
	}
	if c, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = c.SetReadDeadline(time.Time{})
	}
	for {
		typ, b, err = Read(r)
		if err != nil {
			return fmt.Errorf("session disconnected before final capture status; evidence completeness is unknown: %w", err)
		}
		switch typ {
		case Output:
			if err := writeAll(out, b); err != nil {
				return fmt.Errorf("terminal output: %w", err)
			}
		case Finished:
			var result Result
			if err := json.Unmarshal(b, &result); err != nil {
				return fmt.Errorf("invalid final status: %w", err)
			}
			return result.Err()
		default:
			return fmt.Errorf("unexpected server frame: %d", typ)
		}
	}
}
