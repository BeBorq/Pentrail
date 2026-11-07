package capture

import "testing"

// Deterministic checks of goTransition on `go tool trace -d=parsed` lines of
// both known layouts (Go 1.25: Resource=Goroutine(N) ... GoID=N From->To at
// the end; Go 1.27: GoID=N From->To Reason="..."). The lines are copied in
// shape from real output; the Go 1.27 ones are the examples observed with Go
// 1.27.3.
func TestTraceGoTransitionBothLayouts(t *testing.T) {
	type want struct {
		g             int64
		from, to, why string
		ok            bool
	}
	cases := []struct {
		name, line string
		w          want
	}{
		{"1.25 goroutine sleeps", `M=172 P=0 G=1 StateTransition Time=29703841984 Resource=Goroutine(1) Reason="sleep" GoID=1 Running->Waiting`, want{1, "Running", "Waiting", "sleep", true}},
		{"1.25 emitter G=-1, goroutine 9 runs", `M=172 P=0 G=-1 StateTransition Time=29703843200 Resource=Goroutine(9) Reason="" GoID=9 Runnable->Running`, want{9, "Runnable", "Running", "", true}},
		{"1.25 emitter G=1 creates goroutine 7", `M=172 P=0 G=1 StateTransition Time=29703834624 Resource=Goroutine(7) Reason="" GoID=7 NotExist->Runnable`, want{7, "NotExist", "Runnable", "", true}},
		{"1.25 processor", `M=172 P=-1 G=-1 StateTransition Time=29703817856 Resource=Proc(0) Reason="" ProcID=0 Undetermined->Running`, want{ok: false}},
		{"1.27 goroutine sleeps", `M=20864 P=0 G=1 StateTransition Time=1931823486078 GoID=1 Running->Waiting Reason="sleep"`, want{1, "Running", "Waiting", "sleep", true}},
		{"1.27 woken by another emitter", `M=15776 P=1 G=-1 StateTransition Time=1931944110597 GoID=1 Waiting->Runnable Reason=""`, want{1, "Waiting", "Runnable", "", true}},
		{"1.27 runs again", `M=15776 P=1 G=-1 StateTransition Time=1931944119191 GoID=1 Runnable->Running Reason=""`, want{1, "Runnable", "Running", "", true}},
		{"1.27 emitter G=1 affects goroutine 12", `M=15776 P=1 G=1 StateTransition Time=1931944120000 GoID=12 NotExist->Runnable Reason=""`, want{12, "NotExist", "Runnable", "", true}},
		{"1.27 processor", `M=15776 P=1 G=1 StateTransition Time=1931944120001 ProcID=1 Idle->Running Reason=""`, want{ok: false}},
		{"1.27 processor with emitter goroutine", `M=15776 P=1 G=1 StateTransition Time=1931944120002 ProcID=0 Running->Idle Reason="" `, want{ok: false}},
		{"a reason cannot fake a transition", `M=1 P=0 G=3 StateTransition Time=10 GoID=3 Running->Waiting Reason="GoID=9 Running->Dead"`, want{3, "Running", "Waiting", "GoID=9 Running->Dead", true}},
		{"Resource and GoID disagree", `M=1 P=0 G=1 StateTransition Time=10 Resource=Goroutine(2) Reason="" GoID=3 Running->Waiting`, want{ok: false}},
		{"Resource is a processor next to a GoID", `M=1 P=0 G=1 StateTransition Time=10 Resource=Proc(2) Reason="" GoID=2 Running->Idle`, want{ok: false}},
		{"no transition", `M=1 P=0 G=1 StateTransition Time=10 GoID=3 Reason=""`, want{ok: false}},
		{"not a state transition", `M=1 P=0 G=1 RegionBegin Time=10 Task=0 Type="pentrail-redact-step"`, want{ok: false}},
	}
	for _, c := range cases {
		g, from, to, why, ok := goTransition(c.line)
		got := want{g, from, to, why, ok}
		if !c.w.ok {
			if ok {
				t.Errorf("%s: read as goroutine transition %+v", c.name, got)
			}
			continue
		}
		if got != c.w {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.w)
		}
	}
}
