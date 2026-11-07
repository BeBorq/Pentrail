package redact

import (
	"fmt"
	"testing"
)

// Codex 04L: cost of the store's redaction step (Clone + Feed of one 8 KiB
// batch) on the output shapes of the 8 MiB native test: the same synthetic
// content (no LF in the file; ConPTY renders 120-column rows), as rows that
// start with a cursor position (the continuation join) and as plain CRLF
// rows; plus rows with trigger words (the non-quiet path).
func stepShapes() map[string][]byte {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	row := func(i int) []byte {
		b := make([]byte, 120)
		for k := range b {
			j := i*120 + k
			b[k] = abc[(j*7+j/97)%len(abc)]
		}
		return b
	}
	shapes := map[string][]byte{}
	var cup, plainRows, words []byte
	for i := 0; len(cup) < 1<<20; i++ {
		cup = append(append(append(cup, "\x1b[30;1H"...), row(i)...), "\r\n"...)
		plainRows = append(append(plainRows, row(i)...), "\r\n"...)
		words = append(append(append(words, "\x1b[30;1Hnet user admin: token="...), row(i)[:80]...), "\r\n"...)
	}
	shapes["cursor-led rows"], shapes["plain rows"], shapes["cursor-led rows with trigger words"] = cup, plainRows, words
	return shapes
}

// stepRun feeds data in 8 KiB batches exactly as the store does.
func stepRun(data []byte) []byte {
	var s Stream
	var out []byte
	for i := 0; i < len(data); i += 8 << 10 {
		c := s.Clone()
		out = append(out, c.Feed(data[i:min(i+8<<10, len(data))])...)
		s = c
	}
	return append(out, s.Finish()...)
}

func BenchmarkRedactStep(b *testing.B) {
	for name, data := range stepShapes() {
		data := data[:256<<10]
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				stepRun(data)
			}
		})
	}
}

// TestRedactStepCost reports, per 8 KiB step, time, bytes and objects
// allocated (testing.Benchmark), for the record of each iteration.
func TestRedactStepCost(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("measurement")
	}
	for _, name := range []string{"cursor-led rows", "plain rows", "cursor-led rows with trigger words"} {
		data := stepShapes()[name][:256<<10]
		steps := float64(len(data) / (8 << 10))
		r := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stepRun(data)
			}
		})
		t.Log(fmt.Sprintf("STEPCOST %-36s per 8 KiB step: %7.3f ms, %8.1f KiB, %7.0f objects",
			name, float64(r.NsPerOp())/1e6/steps, float64(r.AllocedBytesPerOp())/1024/steps, float64(r.AllocsPerOp())/steps))
	}
}
