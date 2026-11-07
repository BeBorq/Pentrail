package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
)

const detachByte = 0x1c

// maxBatch bounds one durable write of PTY output (ptypump.go). A batch is
// redacted and committed under this session's capture lock, which input and
// control requests of THIS session also take; the lock hold grows with the
// batch (Codex 04G, TestPumpKeepsSessionResponsive and its race-slowed run:
// 32 KiB held up to 4x longer than one PTY read on a slow CPU). 8 KiB keeps
// the hold within the range of one read while halving the commits; it is a
// hard limit (a 32 KiB read is split).
const maxBatch = 8 << 10

// pumpOneReadPerWrite (tests only): one whole PTY read per durable write,
// the loop before 04F, to compare both in the same environment.
var pumpOneReadPerWrite bool

var errDetach = errors.New("session detached")

// RunServer owns the PTY and store. The final result is sent only after the
// database is flushed and closed. A slow client cannot block capture.
func RunServer(opts Options, sockPath string) (runErr error) {
	hub := sessionio.NewHub()
	firstClient := make(chan struct{})
	var firstOnce sync.Once
	hub.SetOnAttach(func() { firstOnce.Do(func() { close(firstClient) }) })
	var ln net.Listener
	var offset, seq int64
	var captureMu sync.Mutex
	recording := true
	// captureErr is set once persistence has failed definitively (a non-lock
	// database error, or a lock held past the retry window). From then on the
	// session keeps relaying the terminal — the shell and the user's work are
	// never killed for a storage problem — but records nothing, says so on the
	// terminal and in `pentrail status`, and reports INCOMPLETE at the end.
	var captureErr error
	observer := newShellObserver(opts)
	exitCode := 0
	defer func() {
		runErr = errors.Join(runErr, opts.Store.FinishSession(opts.SessionID))
		result := sessionio.Result{ExitCode: exitCode, OutputBytes: offset}
		if runErr != nil {
			result.CaptureError = runErr.Error()
		}
		hub.Finish(result)
		if ln != nil {
			ln.Close()
			os.Remove(sockPath)
		}
	}()
	// Bind before spawning so a bad socket path does not leave an orphan shell.
	var err error
	ln, err = localipc.Listen(sockPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", sockPath, err)
	}
	env := append(os.Environ(), "PENTRAIL=1", "PENTRAIL_SESSION="+strconv.FormatInt(opts.SessionID, 10))
	ptmx, err := startPTY(opts.Shell, opts.Args, env)
	if err != nil {
		return fmt.Errorf("starting pty: %w", err)
	}
	defer ptmx.Close()
	var inputClosed atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go hub.ServeConn(conn, func(typ byte, b []byte) error {
				// During final DB flush the PTY is already closed. Keep the
				// connection alive for its result, even if input/resize races exit.
				if inputClosed.Load() {
					return nil
				}
				var inputErr error
				switch typ {
				case sessionio.Data:
					captureMu.Lock()
					observer.Input(b, offset, recording && captureErr == nil)
					captureMu.Unlock()
					_, inputErr = ptmx.Write(b)
				case sessionio.Resize:
					rows, cols := binary.BigEndian.Uint16(b[:2]), binary.BigEndian.Uint16(b[2:])
					if r, ok := observer.(interface{ Resize(cols, rows int) }); ok && rows > 0 && cols > 0 {
						captureMu.Lock()
						r.Resize(int(cols), int(rows)) // the CMD screen model follows the console size
						captureMu.Unlock()
					}
					inputErr = ptmx.Resize(rows, cols)
				}
				if inputClosed.Load() {
					return nil
				}
				return inputErr
			})
		}
	}()
	ingestStop := make(chan struct{})
	var ingestWg sync.WaitGroup
	if opts.ArtifactDir != "" {
		ingestWg.Add(1)
		go func() {
			defer ingestWg.Done()
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ingestStop:
					return
				case <-t.C:
					if _, err := opts.Store.IngestArtifacts(opts.SessionID); err != nil {
						fmt.Fprintln(os.Stderr, "pentrail: artifact ingest:", err)
					}
				}
			}
		}()
	}
	defer func() { close(ingestStop); ingestWg.Wait() }()
	parser := NewParser(opts.MarkerToken,
		func(ev CommandEvent) {
			opts.Store.WriteCommand(store.Command{
				SessionID: opts.SessionID, Index: ev.Index, Command: ev.Command, Cwd: ev.Cwd,
				StartedAt: ev.StartedAt, EndedAt: ev.EndedAt, ExitCode: ev.ExitCode,
				OutStartOff: ev.OutStartOff, OutEndOff: ev.OutEndOff, Complete: ev.Complete && OutputMapping(opts.Shell) == "",
				EndReason: ev.EndReason,
			})
		},
		func(tool, path string, idx int64) {
			if underDir(opts.ArtifactDir, path) {
				opts.Store.WriteArtifact(opts.SessionID, idx, tool, path)
			}
		},
		func(path string) {
			if underDir(opts.ArtifactDir, path) {
				opts.Store.MarkArtifactFinalized(opts.SessionID, path)
			}
		},
	)
	parser.onStart = parser.onCommand
	parserDisabled := false // guarded by captureMu
	if err := opts.Store.RecordCaptureState(opts.SessionID, true, 0); err != nil {
		return fmt.Errorf("record capture state: %w", err)
	}
	hub.SetControl(func(op string) (sessionio.ControlState, error) {
		lockWait := startLockWait() // diagnostics only (flow.go)
		captureMu.Lock()
		defer captureMu.Unlock()
		lockWait.done(opts.SessionID, op)
		state := sessionio.ControlState{SessionID: opts.SessionID, Recording: recording && captureErr == nil, RootPID: ptmx.RootPID(), ConsoleID: ptmx.ConsoleID(), DatabaseID: opts.DatabaseID}
		if captureErr != nil {
			state.CaptureError = captureErr.Error()
		}
		if op == "flush" {
			if e := opts.Store.MaskPendingRaw(opts.SessionID); e != nil {
				return state, e
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return state, opts.Store.Sync(ctx)
		}
		if op == "status" {
			return state, nil
		}
		if inputClosed.Load() {
			return state, fmt.Errorf("session is ending")
		}
		if op != "on" && op != "off" {
			return state, fmt.Errorf("unknown control operation")
		}
		if captureErr != nil && op == "on" {
			return state, fmt.Errorf("recording stopped after a storage failure (%v); end this session and open a new terminal", captureErr)
		}
		enabled := op == "on"
		if enabled == recording {
			return state, nil
		}
		if !enabled {
			// a command still running keeps what was recorded so far
			if !parserDisabled {
				parser.CloseOpen(offset, store.EndRecordingPaused)
			}
			observer.Reset(offset)
			recording = false
			if e := opts.Store.PauseCapture(opts.SessionID); e != nil {
				return state, e
			}
			parser.DiscardBoundary()
		}
		err := opts.Store.RecordCaptureState(opts.SessionID, enabled, offset)
		if err == nil && enabled {
			parser.DiscardBoundary()
			observer.Reset(offset)
			opts.Store.ResumeCapture(opts.SessionID)
			recording = true
		}
		state.Recording = recording
		return state, err
	})
	// Preserve the initial prompt/rc output in the PTY buffer until the first
	// real client registers. Health/control probes do not release this gate.
	// If the starting client dies before connecting, capture starts anyway.
	select {
	case <-firstClient:
	case <-time.After(2 * time.Second):
	}
	// Batches: everything already read while the previous batch was being
	// made durable (ptypump.go); stored, then shown, in order.
	pump := newPTYPump(ptmx)
	defer pump.stop()
	for {
		fl := startFlow() // nil unless a diagnostic test measures the output path
		var buf []byte
		var rerr error
		if pumpOneReadPerWrite {
			buf, rerr = pump.nextRead()
		} else {
			buf, rerr = pump.next(maxBatch)
		}
		n := len(buf)
		fl.lap(flowRead)
		if n > 0 {
			var notice []byte
			captureMu.Lock()
			fl.locked()
			active := recording && captureErr == nil
			observer.Output(buf[:n], offset, active)
			fl.lap(flowObserver)
			if active {
				if !parserDisabled {
					parserDisabled = feedSafely(parser, buf[:n], offset)
				}
				fl.lap(flowParser)
				if e := opts.Store.WriteRaw(opts.SessionID, seq, offset, buf[:n]); e != nil {
					captureErr = e
					runErr = fmt.Errorf("durable capture failed: %w", e)
					fmt.Fprintln(os.Stderr, "pentrail: RECORDING STOPPED — storage failure; the shell keeps running unrecorded:", e)
					notice = []byte("\r\n[pentrail] WARNING: recording of this session STOPPED after a database error: " + e.Error() +
						"\r\n[pentrail] The shell keeps running, but from now on NOTHING is recorded. End the session and open a new terminal.\r\n")
				} else {
					seq++
					offset += int64(n)
				}
			} else if recording {
				// storage failed: nothing more is written, not even the privacy state
			} else {
				opts.Store.ObservePaused(opts.SessionID, buf[:n])
			}
			fl.lap(flowStore)
			fl.unlocked()
			captureMu.Unlock()
			hub.Publish(buf[:n])
			if notice != nil {
				hub.Publish(notice) // shown on the terminal only; it is not evidence
			}
			fl.lap(flowPublish)
			fl.done(opts.SessionID, n, offset)
		}
		if rerr != nil {
			inputClosed.Store(true)
			// EOF: close what is still open at the end of the captured output.
			captureMu.Lock()
			if recording && captureErr == nil {
				if !parserDisabled {
					parser.CloseOpen(offset, store.EndSessionEnded)
				}
				observer.Close(offset)
			}
			captureMu.Unlock()
			if !errors.Is(rerr, io.EOF) && !errors.Is(rerr, syscall.EIO) {
				runErr = fmt.Errorf("PTY read: %w", rerr)
				_ = ptmx.Kill()
			}
			break
		}
	}
	code, waitErr := ptmx.Wait()
	exitCode = code
	runErr = errors.Join(runErr, waitErr)
	return runErr
}
