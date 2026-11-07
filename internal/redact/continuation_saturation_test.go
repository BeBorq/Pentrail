package redact

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestContinuationSaturationGuard(t *testing.T) {
	for _, tc := range []struct {
		context, head string
		want          bool
	}{
		{`password="word word `, "word word next", true},
		{"password=\"abc\x1b[31mHELLO", "mHELLO next", false},
		{"password=\"abc\x1b[?", "next", false},
		{"password=\"abc\x1b[?\x1b", "next", false},
		{"password=\"abc\x1b", "next", true},
		{"password=\"abc\x1b]0;title\a", "next", false},
	} {
		got := continuationSaturationSafe([]byte(tc.context), []byte("\x1b[30;1H"+tc.head+"\r\n"), []byte(tc.head+"\r\n"))
		if got != tc.want {
			t.Errorf("context=%q head=%q got=%v want=%v", tc.context, tc.head, got, tc.want)
		}
	}
}

func TestSaturatedContinuationExactReference(t *testing.T) {
	defer func() { prefilterOff = false }()
	check := func(context, row []byte, mode int) {
		t.Helper()
		s := Stream{context: append([]byte(nil), context...), pending: append([]byte(nil), row...), pem: mode&1 != 0, nextSecretLine: mode&2 != 0}
		ref := s.Clone()
		got := s.finishLine()
		prefilterOff = true
		want := ref.finishLineRef()
		prefilterOff = false
		if !bytes.Equal(got, want) || s.Changed != ref.Changed || !bytes.Equal(s.context, ref.context) || !bytes.Equal(s.pending, ref.pending) || !bytes.Equal(s.prefix, ref.prefix) || s.pem != ref.pem || s.closedLine != ref.closedLine || s.nextSecretLine != ref.nextSecretLine {
			t.Fatalf("context=%q row=%q mode=%d\ngot=%q\nwant=%q\nstate=%+v\nreference=%+v", context, row, mode, got, want, s, ref)
		}
	}
	contexts := []string{`password="` + strings.Repeat("word ", 30), `token='` + strings.Repeat("word ", 30), "password=\"abc\x1b[31mHELLO", "password=\"abc\x1b[?\x1b", "password=\"abc\x1b", "password=\"abc\x1b]0;title\a"}
	for _, context := range contexts {
		for _, head := range []string{strings.Repeat("word ", 20), "mHELLO next", "\x1b[?next", "text\x1b]0;title\aend"} {
			for mode := 0; mode < 4; mode++ {
				check([]byte(context), []byte("\x1b[30;1H"+head+"\r\n"), mode)
			}
		}
	}
	r := rand.New(rand.NewSource(61820))
	alphabet := []byte("word password=token:'\"; \x1b[?31mH]\a\r\n")
	for n := 0; n < 1800; n++ {
		ctx := []byte(`password="`)
		for i := r.Intn(250); i > 0; i-- {
			ctx = append(ctx, alphabet[r.Intn(len(alphabet))])
		}
		overlap := r.Intn(min(64, len(ctx)) + 1)
		head := append([]byte(nil), ctx[len(ctx)-overlap:]...)
		for i := r.Intn(100); i > 0; i-- {
			head = append(head, alphabet[r.Intn(len(alphabet))])
		}
		row := append([]byte("\x1b[30;1H"), head...)
		row = append(row, '\r', '\n')
		check(ctx, row, n%4)
	}
}
