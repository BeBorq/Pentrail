//go:build windows

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/signal"
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
	var outMode uint32
	outHandle := windows.Handle(os.Stdout.Fd())
	if windows.GetConsoleMode(outHandle, &outMode) == nil {
		_ = windows.SetConsoleMode(outHandle, outMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		defer windows.SetConsoleMode(outHandle, outMode)
	}
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	inputDone := make(chan error, 1)
	send := func(typ byte, b []byte) error {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		return w.Send(typ, b)
	}
	var lastRows, lastCols uint16
	resize := func() {
		rows, cols := consoleSize()
		if rows == lastRows && cols == lastCols {
			return
		}
		lastRows, lastCols = rows, cols
		var b [4]byte
		binary.BigEndian.PutUint16(b[:2], rows)
		binary.BigEndian.PutUint16(b[2:], cols)
		_ = send(sessionio.Resize, b[:])
	}
	resize()
	go func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				resize()
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		filter := detachFilter{}
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data, detach := filter.Feed(buf[:n])
				if len(data) > 0 {
					if e := send(sessionio.Data, data); e != nil {
						inputDone <- e
						return
					}
				}
				if detach {
					inputDone <- errDetach
					return
				}
			}

			if err != nil {
				// Piped input ending is not proof that the shell/capture ended.
				// Continue receiving the final result unless explicitly detached.
				if pending := filter.Flush(); len(pending) > 0 {
					_ = send(sessionio.Data, pending)
				}
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
