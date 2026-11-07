package redact

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestContinuationQuietCrossBoundaryLiteral(t *testing.T) {
	context := []byte(strings.Repeat("public ", 30) + "tok")
	row := []byte("\x1b[30;1Hken=foo\r\n")
	sc := getScratch()
	defer putScratch(sc)
	joined := append(append([]byte(nil), context...), row...)
	if !quietWith(joined, sc) {
		t.Fatal("fixture must be quiet before de-duplication")
	}
	var q continuationQuietCache
	q.init(context, row, sc.found)
	if !q.enabled || q.quiet(context, 1) {
		t.Fatal("removing the duplicated k creates token=foo and must not be skipped")
	}
	s := Stream{context: context, pending: row}
	got := s.finishLine()
	if !bytes.Contains(got, []byte("ken=***")) {
		t.Fatalf("new cross-boundary credential not masked: %q", got)
	}
}

func TestContinuationQuietProofAgainstOriginal(t *testing.T) {
	defer func() { prefilterOff = false }()
	r := rand.New(rand.NewSource(61821))
	alphabet := []byte("public abcdefghijklmnoptuvwxyz =;_-:'\"")
	checked := 0
	for n := 0; n < 1200; n++ {
		context := []byte("Zażółć\x1b[0m" + strings.Repeat("public ", 25))
		for i := r.Intn(80); i > 0; i-- {
			context = append(context, alphabet[r.Intn(len(alphabet))])
		}
		k := r.Intn(65)
		head := append([]byte(nil), context[len(context)-k:]...)
		for i := r.Intn(70); i > 0; i-- {
			head = append(head, alphabet[r.Intn(len(alphabet))])
		}
		row := append([]byte("\x1b[30;1H"), head...)
		row = append(row, '\r', '\n')
		sc := getScratch()
		joined := append(append([]byte(nil), context...), row...)
		if quietWith(joined, sc) {
			var q continuationQuietCache
			q.init(context, row, sc.found)
			if q.enabled {
				for overlap := 1; overlap <= min(64, min(len(context), len(head))); overlap++ {
					if !bytes.Equal(context[len(context)-overlap:], head[:overlap]) || !q.quiet(context, overlap) {
						continue
					}
					prefix := context[:len(context)-overlap]
					v := append(append([]byte(nil), prefix...), row...)
					prefilterOff = true
					clean := line(v)
					prefilterOff = false
					if !bytes.Equal(clean[len(prefix):], row) {
						t.Fatalf("false quiet proof: context=%q row=%q overlap=%d result=%q", context, row, overlap, clean[len(prefix):])
					}
					checked++
				}
			}
		}
		putScratch(sc)
	}
	if checked == 0 {
		t.Fatal("no eligible overlap exercised")
	}
	t.Logf("%d shortcut proofs checked against original full regex path", checked)
}
