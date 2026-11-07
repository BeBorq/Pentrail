package capture

import (
	"encoding/base64"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

// CloseOpen closes only a command whose output is open (C without D), with
// the captured range, unknown exit status and the reason; nothing otherwise.
func TestParserCloseOpen(t *testing.T) {
	const tok = "closetok"
	const esc, bel = "\x1b]", "\x07"
	cmd := base64.StdEncoding.EncodeToString([]byte("nmap -p- 10.0.0.1"))
	var got []CommandEvent
	p := NewParser(tok, func(ev CommandEvent) { got = append(got, ev) }, nil, nil)
	p.onStart = p.onCommand
	p.CloseOpen(0, store.EndSessionEnded)
	if len(got) != 0 {
		t.Fatal("closed a command that was never started")
	}
	in := esc + "697;" + tok + ";CMD;" + cmd + bel + esc + "697;" + tok + ";C" + bel + "Starting Nmap\r\npartial\r\n"
	p.Feed([]byte(in), 0)
	end := int64(len(in))
	p.CloseOpen(end, store.EndRecordingPaused)
	if len(got) != 2 {
		t.Fatalf("events %+v", got)
	}
	c := got[1]
	if c.Command != "nmap -p- 10.0.0.1" || c.EndedAt == 0 || c.OutEndOff != end || c.OutEndOff <= c.OutStartOff ||
		c.ExitCode != -1 || c.Complete || c.EndReason != store.EndRecordingPaused || c.Index != got[0].Index {
		t.Fatalf("closed event: %+v", c)
	}
	p.CloseOpen(end+10, store.EndSessionEnded)
	if len(got) != 2 {
		t.Fatal("closed twice")
	}
}
