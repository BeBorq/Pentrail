package capture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// TestReplayCMDTrace replays a trace recorded by a native CMD test (see
// cmd_evidence_windows_test.go) through the platform-independent segmenter,
// on any OS:
//
//	PENTRAIL_CMD_TRACE=<evidence folder of one test> go test -run TestReplayCMDTrace -v ./internal/capture
//
// It first proves the replay is faithful: the rows (and unattributed counts)
// produced now must equal, in order, those the live session wrote (times
// excluded). Only then does it print every prompt marker with its offset
// and, for every command, its range and the bytes in that range — material
// for diagnosing the assignment. It asserts nothing about which assignment
// is correct (Codex iteration 04A: diagnosis first).
func TestReplayCMDTrace(t *testing.T) {
	dir := os.Getenv("PENTRAIL_CMD_TRACE")
	if dir == "" {
		t.Skip("set PENTRAIL_CMD_TRACE to an evidence folder")
	}
	r, err := replayCMD(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A trace recorded by the SAME segmenter version must replay identically
	// (PENTRAIL_CMD_TRACE_STRICT=1). Traces recorded by an older version (the
	// 04A fixtures) are expected to differ once a defect is fixed: both are
	// printed, the fixture's expected results are asserted in
	// TestNativeFixtureCMD.
	if !r.faithful() {
		msg := fmt.Sprintf("replay differs from the live session:\n--- live (recording version)\n%s\n--- replay (this version)\n%s",
			strings.Join(r.want, "\n"), strings.Join(r.got, "\n"))
		if os.Getenv("PENTRAIL_CMD_TRACE_STRICT") == "1" {
			t.Fatal(msg)
		}
		t.Log(msg)
	} else {
		t.Logf("replay identical to the live session: %d events, %d writes/notes", r.events, len(r.want))
	}
	for _, n := range r.notes {
		t.Log(n)
	}
	// 04D: the segmenter's decisions while replaying (prompt candidates,
	// superseded/answered/repaint, closed lines and why they did or did not
	// become commands), and whether the live log (if recorded) matches.
	for _, d := range r.decisions {
		t.Log("seg: " + d)
	}
	if len(r.liveDecisions) > 0 {
		t.Logf("live decision log: %d lines, identical to replay: %v", len(r.liveDecisions),
			strings.Join(r.liveDecisions, "\n") == strings.Join(r.decisions, "\n"))
	}
	out := r.stream
	if raw, err := os.ReadFile(filepath.Join(dir, "raw.bin")); err == nil {
		t.Logf("raw.bin %d bytes (masked, same offsets); output events %d bytes", len(raw), len(out))
		if len(raw) == len(out) {
			out = raw // what the viewer shows
		}
	}
	marker := []byte("\x1b]697;" + r.token + ";A")
	for i := 0; ; {
		k := bytes.Index(out[i:], marker)
		if k < 0 {
			break
		}
		t.Logf("prompt marker at %d", i+k)
		i += k + len(marker)
	}
	for idx := int64(0); idx < int64(len(r.final)); idx++ {
		c := r.final[idx]
		lo, hi := c.OutStartOff, c.OutEndOff
		if lo < 0 || hi > int64(len(out)) || hi < lo {
			t.Logf("#%d %q range %d..%d INVALID for %d bytes", idx, c.Command, lo, hi, len(out))
			continue
		}
		t.Logf("#%d %q range %d..%d reason=%q: %q", idx, c.Command, lo, hi, c.EndReason, out[lo:hi])
	}
}

type cmdReplay struct {
	got, want, notes []string
	decisions        []string                // the replaying segmenter's decision log (04D)
	liveDecisions    []string                // "seg" events recorded live, if any
	final            map[int64]store.Command // replay: last row per index
	live             map[int64]store.Command // recorded: last row per index
	liveNotes        int64
	gotNotes         int64
	stream           []byte
	token            string
	events           int
}

func (r *cmdReplay) faithful() bool { return strings.Join(r.got, "\n") == strings.Join(r.want, "\n") }

func replayCMD(dir string) (*cmdReplay, error) {
	f, err := os.Open(filepath.Join(dir, "trace.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []SegTraceEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev SegTraceEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("trace line %d: %w", len(events)+1, err)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 || events[0].Ev != "start" {
		return nil, errors.New("trace does not begin with a start event")
	}
	r := &cmdReplay{final: map[int64]store.Command{}, live: map[int64]store.Command{}, token: events[0].Tok, events: len(events)}
	row := func(c store.Command) string {
		return fmt.Sprintf("write idx=%d cmd=%q out=%d..%d reason=%q exit=%d complete=%v ended=%v",
			c.Index, c.Command, c.OutStartOff, c.OutEndOff, c.EndReason, c.ExitCode, c.Complete, c.EndedAt != 0)
	}
	seg := newCmdSegmenter(events[0].Tok, events[0].ID,
		func(c store.Command) { r.got = append(r.got, row(c)); r.final[c.Index] = c },
		func(n int64) { r.got = append(r.got, fmt.Sprintf("note n=%d", n)); r.gotNotes += n })
	seg.dbg = func(format string, args ...any) { r.decisions = append(r.decisions, fmt.Sprintf(format, args...)) }
	var stream bytes.Buffer // output as the segmenter saw it (unmasked)
	for _, ev := range events[1:] {
		switch ev.Ev {
		case "seg":
			r.liveDecisions = append(r.liveDecisions, ev.Note)
		case "input":
			seg.Input(ev.Dec, ev.Off, ev.Rec)
		case "output":
			if ev.Off != int64(stream.Len()) {
				r.notes = append(r.notes, fmt.Sprintf("NOTE output event seq=%d at offset %d, stream so far %d (paused recording or gap)", ev.Seq, ev.Off, stream.Len()))
			}
			stream.Write(ev.Raw)
			seg.Output(ev.Raw, ev.Off, ev.Rec)
		case "reset":
			seg.Reset(ev.Off)
		case "close":
			seg.Close(ev.Off)
		case "write":
			if ev.Cmd == nil {
				return nil, fmt.Errorf("write event seq=%d without a row", ev.Seq)
			}
			r.want = append(r.want, row(*ev.Cmd))
			r.live[ev.Cmd.Index] = *ev.Cmd
		case "note":
			r.want = append(r.want, fmt.Sprintf("note n=%d", ev.N))
			r.liveNotes += ev.N
		case "resize":
			seg.Resize(ev.Cols, ev.Rows)
		default:
			return nil, fmt.Errorf("unknown event %q", ev.Ev)
		}
	}
	r.stream = stream.Bytes()
	return r, nil
}

// Self-check of the trace format and the replay tool on a trace produced by
// the core segmenter itself in this test (NOT Windows data): a recorded run
// must replay to identical writes, and a tampered trace must be rejected.
func TestReplayToolSelfCheck(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "trace.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	emit := func(ev SegTraceEvent) {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	emit(SegTraceEvent{Ev: "start", Tok: segTok, ID: 1})
	seg := newCmdSegmenter(segTok, 1,
		func(c store.Command) { emit(SegTraceEvent{Ev: "write", Cmd: &c}) },
		func(n int64) { emit(SegTraceEvent{Ev: "note", N: n}) })
	var off int64
	out := func(s string) {
		emit(SegTraceEvent{Ev: "output", Off: off, Rec: true, Raw: []byte(s)})
		seg.Output([]byte(s), off, true)
		off += int64(len(s))
	}
	in := func(s string) {
		emit(SegTraceEvent{Ev: "input", Off: off, Rec: true, Raw: []byte(s), Dec: []byte(s)})
		seg.Input([]byte(s), off, true)
	}
	out(prompt())
	in("echo A\recho B\rexit\r")
	out("echo A\r\nA\r\n\r\n" + prompt() + "echo B\r\nB\r\n")
	emit(SegTraceEvent{Ev: "close", Off: off})
	seg.Close(off)
	f.Close()
	r, err := replayCMD(dir)
	if err != nil || !r.faithful() || len(r.want) == 0 {
		t.Fatalf("self-recorded trace does not replay faithfully: %v\n%v\n%v", err, r.want, r.got)
	}
	if c := r.final[1]; c.Command != "echo B" || string(r.stream[c.OutStartOff:c.OutEndOff]) != "\r\nB\r\n" {
		t.Fatalf("replayed ranges: %+v", r.final)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "trace.jsonl"))
	bad := bytes.Replace(b, []byte(`"Command":"echo B"`), []byte(`"Command":"echo C"`), 1)
	if bytes.Equal(b, bad) {
		t.Fatal("self-check could not tamper the trace")
	}
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "trace.jsonl"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if r2, err := replayCMD(dir2); err != nil || r2.faithful() {
		t.Fatalf("tampered trace accepted as faithful (err %v)", err)
	}
}
