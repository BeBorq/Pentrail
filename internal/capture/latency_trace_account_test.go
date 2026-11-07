package capture

import (
	"strings"
	"testing"
	"time"
)

// parsedTrace builds the `go tool trace -d=parsed` text of one redaction step
// region on goroutine 1 that sleeps 120 µs, in the layout of Go 1.25 (old) or
// Go 1.27 (new). Between its transitions are processor transitions, a
// transition of another goroutine emitted BY goroutine 1, and a transition of
// goroutine 1 emitted by another (G=-1), so attribution is checked too.
func parsedTrace(newLayout bool) string {
	gt := func(emitter string, t, goid, from, to, why string) string {
		if newLayout {
			return "M=10 P=0 G=" + emitter + " StateTransition Time=" + t + " GoID=" + goid + " " + from + "->" + to + ` Reason="` + why + `"`
		}
		return "M=10 P=0 G=" + emitter + " StateTransition Time=" + t + " Resource=Goroutine(" + goid + `) Reason="` + why + `" GoID=` + goid + " " + from + "->" + to
	}
	pt := func(t, proc, from, to string) string {
		if newLayout {
			return "M=10 P=0 G=1 StateTransition Time=" + t + " ProcID=" + proc + " " + from + "->" + to + ` Reason=""`
		}
		return "M=10 P=0 G=1 StateTransition Time=" + t + " Resource=Proc(" + proc + `) Reason="" ProcID=` + proc + " " + from + "->" + to
	}
	return strings.Join([]string{
		"M=10 P=0 G=1 RegionBegin Time=1000 Task=0 Type=\"" + stepRegion + "\"",
		gt("1", "1050", "7", "NotExist", "Runnable", ""), // goroutine 1 creates goroutine 7: not a change of 1
		gt("1", "1100", "1", "Running", "Waiting", "sleep"),
		pt("1150", "0", "Running", "Idle"),
		gt("-1", "1200", "7", "Runnable", "Running", ""),
		gt("-1", "121100", "1", "Waiting", "Runnable", ""), // woken by another emitter
		pt("121150", "0", "Idle", "Running"),
		gt("-1", "121200", "1", "Runnable", "Running", ""),
		"M=10 P=0 G=1 RegionEnd Time=121300 Task=0 Type=\"" + stepRegion + "\"",
		"",
	}, "\n")
}

func TestTraceAccountingParsedTextBothLayouts(t *testing.T) {
	for _, layout := range []struct {
		name string
		new  bool
	}{{"Go 1.25 layout", false}, {"Go 1.27 layout", true}} {
		text := parsedTrace(layout.new)
		regs, err := findRegions(strings.NewReader(text))
		if err != nil || len(regs) != 1 || regs[0].g != 1 || regs[0].dur() != 120300 {
			t.Fatalf("%s: regions %+v %v", layout.name, regs, err)
		}
		acc, err := accountRegions(strings.NewReader(text), regs)
		if err != nil || len(acc) != 1 {
			t.Fatalf("%s: %v %v", layout.name, acc, err)
		}
		a := acc[0]
		want := map[string]time.Duration{"Running": 200, "Waiting(sleep)": 120000, "Runnable": 100}
		if len(a.inState) != len(want) {
			t.Errorf("%s: states %v, want %v", layout.name, a.inState, want)
		}
		for k, v := range want {
			if a.inState[k] != v {
				t.Errorf("%s: %s = %v, want %v (all: %v)", layout.name, k, a.inState[k], v, a.inState)
			}
		}
		var sum time.Duration
		for _, d := range a.inState {
			sum += d
		}
		if sum != a.r.dur() {
			t.Errorf("%s: states add up to %v, region is %v", layout.name, sum, a.r.dur())
		}
		if a.trans != 3 {
			t.Errorf("%s: %d state changes counted, want 3 (processor and goroutine-7 transitions must not count)", layout.name, a.trans)
		}
		if s := a.String(); !strings.Contains(s, "Waiting(sleep)") || !strings.Contains(s, "(3 state changes)") {
			t.Errorf("%s: report %q", layout.name, s)
		}
	}
}
