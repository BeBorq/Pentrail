//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/creack/pty"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunClient rejects disconnects without a final capture result. Input and resize
// share a Writer that serializes whole frames, including short writes.
func RunClient(sockPath string) error {
	conn, err := localipc.Dial(sockPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("attach %s: %w", sockPath, err)
	}
	defer conn.Close()
	w := sessionio.NewWriter(conn)
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := w.Send(sessionio.Hello, []byte(sessionio.Version)); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if IsTerminal(os.Stdin.Fd()) {
		old, err := MakeRaw(os.Stdin.Fd())
		if err != nil {
			return fmt.Errorf("terminal raw mode: %w", err)
		}
		defer Restore(os.Stdin.Fd(), old)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	inputDone := make(chan error, 1)
	send := func(typ byte, b []byte) error {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		return w.Send(typ, b)
	}
	resize := func() {
		if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
			var b [4]byte
			binary.BigEndian.PutUint16(b[:2], ws.Rows)
			binary.BigEndian.PutUint16(b[2:], ws.Cols)
			if err := send(sessionio.Resize, b[:]); err != nil {
				select {
				case inputDone <- err:
				default:
				}
			}
		}
	}
	resize()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-winch:
				resize()
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if i := indexByte(buf[:n], detachByte); i >= 0 {
					if i > 0 {
						if err := send(sessionio.Data, buf[:i]); err != nil {
							inputDone <- err
							return
						}
					}
					inputDone <- errDetach
					return
				}
				if err := send(sessionio.Data, buf[:n]); err != nil {
					inputDone <- err
					return
				}
			}
			if err != nil {
				// Piped input ending is not proof that the shell/capture ended.
				// Continue receiving the final result unless explicitly detached.
				if !errors.Is(err, io.EOF) {
					inputDone <- err
				}
				return
			}
		}
	}()
	outputDone := make(chan error, 1)
	go func() { outputDone <- sessionio.Receive(conn, os.Stdout) }()
	select {
	case err := <-outputDone:
		return err
	case <-ctx.Done():
		return fmt.Errorf("client interrupted; session may still be running: %w", ctx.Err())
	case err := <-inputDone:
		if errors.Is(err, errDetach) {
			fmt.Fprint(os.Stderr, "\r\npentrail: detached — session keeps running. Re-attach with 'pentrail attach'.\r\n")
			return nil
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		select {
		case resultErr := <-outputDone:
			return resultErr
		case <-ctx.Done():
			return err
		case <-time.After(3 * time.Second):
			return fmt.Errorf("session input failed; final capture status is unknown: %w", err)
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
