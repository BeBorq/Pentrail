package redact

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// plainAll is plain() without the prefilter: every pattern is run.
func plainAll(b []byte) {
	original := append([]byte(nil), b...)
	for _, re := range patterns {
		for _, m := range re.FindAllSubmatchIndex(original, -1) {
			for j := 2; j < len(m); j += 2 {
				if m[j] >= 0 {
					mask(b[m[j]:m[j+1]])
				}
			}
		}
	}
}

// The prefilter must never change a result: on many generated texts built
// from the patterns' own vocabulary (every literal, case and simple-fold
// variants such as KELVIN SIGN and LONG S, separators, quotes, URLs, OSC and
// CSI bytes) plain() and plainAll() give byte-identical output. Also every
// pattern has its literal list.
func TestPrefilterIsExact(t *testing.T) {
	if len(patternNeeds) != len(patterns) {
		t.Fatalf("%d literal lists for %d patterns", len(patternNeeds), len(patterns))
	}
	vocab := []string{"password", "PASSWORD", "Pa\u017f\u017fword", "passwd", "passphrase", "secret", "TOKEN", "to\u212aen", "api_key", "api-key", "apikey",
		"hasło", "HASŁO", "haslo", "pwd", "PWD", "curl", "wget.exe", "-u", "--user", "net", "net.exe", "user", "ConvertTo-SecureString", "-String",
		"identified", "by", "with", "cookie", "set-cookie", "Cookie", "is", "to", "--password", "-p", "--token", "--client-secret", "--hashes",
		"authorization", "Proxy-Authorization", "basic", "Bearer", "http://", "https://", "ftp://", "localhost", "127.0.0.1", ":8080", "/?t=", "abc123",
		"@", ":", "=", `"`, "'", "<", ">", "</", "<password>", "</password>", "<api_key x=1>", "sshpass", "mysql", "nxc", "psexec.py", "hydra",
		"AKIA", "AKIAABCDEFGHIJKLMNOP", "akiaabcdefghijklmnop", "eyJ", "eyJhbGciOi", ".", "x.y", "_", "-", " ", "  ", "\t", "\r", "\n", "\r\n",
		"\x1b[1m", "\x1b[0m", "\x1b]0;title\x07", "\x1b[29;120H", "secretvalue", "S3cr3t!", "pa ss", "\xff", "żółć", "user:pw", "a", "b"}
	rng := rand.New(rand.NewSource(4))
	cases, labels := 0, 0
	for i := 0; i < 200000; i++ {
		var sb strings.Builder
		for k := rng.Intn(12) + 1; k > 0; k-- {
			sb.WriteString(vocab[rng.Intn(len(vocab))])
		}
		a := []byte(sb.String())
		b := append([]byte(nil), a...)
		plain(a)
		plainAll(b)
		if string(a) != string(b) {
			t.Fatalf("prefilter changed the result for %q:\n%q\n%q", sb.String(), a, b)
		}
		if string(a) != sb.String() {
			cases++
		}
		// line() on the same text: fast path and one-pass literal scan
		// against the reference (prefilterOff: every pattern, no fast path)
		fast := line([]byte(sb.String()))
		prefilterOff = true
		ref := line([]byte(sb.String()))
		prefilterOff = false
		if string(fast) != string(ref) {
			t.Fatalf("line() fast path changed the result for %q:\n%q\n%q", sb.String(), fast, ref)
		}
		// Codex 04T: emptySecretLabel's prefilter against the plain
		// expression, on the text and on the text followed by each kind of
		// trailing space bytes.TrimSpace removes (ASCII, \v, NEL, NBSP)
		for k, sfx := range labelSuffixes {
			if k > 0 && i%5 != 0 {
				continue // every text bare; every 5th also with each suffix
			}
			x := []byte(sb.String() + sfx)
			got := emptySecretLabel(x)
			if want := emptyLabel.Match(bytes.TrimSpace(x)); got != want {
				t.Fatalf("emptySecretLabel(%q) = %v, the expression says %v", x, got, want)
			}
			if got {
				labels++
			}
		}
	}
	if cases < 1000 {
		t.Fatalf("only %d generated texts contained a secret: the generator does not exercise the patterns", cases)
	}
	if labels < 1000 {
		t.Fatalf("only %d generated texts end with an empty secret label: the check is not exercised", labels)
	}
	t.Logf("200000 texts, %d with masked secrets, identical with and without the prefilter (plain and line); emptySecretLabel identical to its expression (%d true)", cases, labels)

	// Codex 04L: the same texts as ConPTY rows through the Stream —
	// cursor-led rows (the continuation join with its candidate overlaps,
	// including rows that repaint the end of the previous one), plain rows,
	// split at random batch boundaries — must give byte-identical output,
	// the same Changed count and the same internal state with the current
	// code (reused buffers, quiet candidates skipped) and with the pre-04L
	// code (streamref_test.go) run with every pattern (prefilterOff).
	rows := 3000
	if raceEnabled {
		rows = 400
	}
	streamCases, streamMasked := 0, 0
	for run := 0; run < 4; run++ {
		var text []byte
		prev := ""
		for r := 0; r < rows/4; r++ {
			var sb strings.Builder
			for k := rng.Intn(8) + 1; k > 0; k-- {
				sb.WriteString(vocab[rng.Intn(len(vocab))])
			}
			row := sb.String()
			if n := rng.Intn(24); rng.Intn(4) == 0 && n > 0 && n <= len(prev) { // repaint of the previous row's end
				row = prev[len(prev)-n:] + row
			}
			prev = row
			if rng.Intn(5) > 0 {
				text = append(text, fmt.Sprintf("\x1b[%d;1H", 1+rng.Intn(30))...)
			}
			text = append(text, row...)
			text = append(text, "\r\n"...)
		}
		// both streams in lockstep: output, Changed AND the internal state
		// (pending line, recognition context: the chosen overlap) after
		// every batch
		r := rand.New(rand.NewSource(int64(run)))
		var fastSt, refSt Stream
		var fast, ref []byte
		for i := 0; i < len(text); {
			n := min(len(text)-i, 1+r.Intn(8<<10))
			c := fastSt.Clone()
			fast = append(fast, c.Feed(text[i:i+n])...)
			fastSt = c
			prefilterOff = true
			c = refSt.Clone()
			ref = append(ref, c.feedRef(text[i:i+n])...) // the pre-04L code
			refSt = c
			prefilterOff = false
			if string(fastSt.context) != string(refSt.context) || string(fastSt.pending) != string(refSt.pending) ||
				fastSt.nextSecretLine != refSt.nextSecretLine || fastSt.pem != refSt.pem || fastSt.closedLine != refSt.closedLine {
				t.Fatalf("stream run %d: state differs after byte %d: context %q vs %q", run, i+n,
					fastSt.context[max(0, len(fastSt.context)-60):], refSt.context[max(0, len(refSt.context)-60):])
			}
			i += n
		}
		fast = append(fast, fastSt.Finish()...)
		prefilterOff = true
		ref = append(ref, refSt.Finish()...)
		prefilterOff = false
		fc, rc := fastSt.Changed, refSt.Changed
		if string(fast) != string(ref) || fc != rc {
			i := 0
			for i < len(fast) && i < len(ref) && fast[i] == ref[i] {
				i++
			}
			t.Fatalf("stream run %d differs at byte %d (changed %d vs %d): fast %q ref %q", run, i, fc, rc,
				fast[max(0, i-40):min(len(fast), i+40)], ref[max(0, i-40):min(len(ref), i+40)])
		}
		streamCases++
		if rc > 0 {
			streamMasked++
		}
	}
	if streamMasked == 0 {
		t.Fatal("no stream run masked anything: the stream check does not exercise the patterns")
	}
	t.Logf("stream: %d runs of %d rows (cursor-led, repainted, plain; random batches), identical with and without the fast paths", streamCases, rows/4)
}

// Throughput on ConPTY-like output (rows starting with a cursor position,
// the continuation join) and on plain rows; also text full of trigger
// words. Reported, and bounded: no 4 KiB may cost hundreds of ms.
func TestRedactThroughputConPTYRows(t *testing.T) {
	row := func(i int) string {
		const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, 120)
		for k := range b {
			b[k] = abc[((i*120+k)*7+(i*120+k)/97)%36]
		}
		return string(b)
	}
	shapes := map[string]func(i int) string{
		"plain rows CRLF":         func(i int) string { return row(i) + "\r\n" },
		"rows starting with CUP":  func(i int) string { return "\x1b[30;1H" + row(i) + "\r\n" },
		"CUP rows, trigger words": func(i int) string { return "\x1b[30;1Hnet user admin: token=" + row(i)[:80] + "\r\n" },
	}
	for name, f := range shapes {
		var b []byte
		for i := 0; len(b) < 256<<10; i++ {
			b = append(b, f(i)...)
		}
		var s Stream
		var worst float64
		total := 0.0
		for i := 0; i < len(b); i += 4096 {
			t0 := nowSeconds()
			s.Feed(b[i:min(i+4096, len(b))])
			d := nowSeconds() - t0
			total += d
			worst = max(worst, d)
		}
		t.Logf("REDACT %-24s 256KiB: %.0f ms (%.2f MiB/s), worst 4KiB %.1f ms", name, total*1000, 0.25/total, worst*1000)
		if worst > 0.1 && !raceEnabled { // the race detector slows everything ~10x
			t.Fatalf("%s: a 4 KiB chunk took %.0f ms", name, worst*1000)
		}
	}
}

// labelSuffixes: what may follow a label on its line — nothing, ASCII
// spaces, and the other spaces bytes.TrimSpace removes.
var labelSuffixes = []string{"", " ", "\t", "\r", "\f", "\v", "  \t", "\u0085", "\u00a0", " \u00a0 "}

// Codex 04T: fixed cases around the prefilter's reasoning — the separator
// must be the last non-space byte; spaces TrimSpace removes (also \v, NEL,
// NBSP) may follow; anything else after it (an escape sequence, text, an
// invalid byte) makes it false; Unicode case folding (ſ, K) still counts.
func TestEmptySecretLabelCases(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"password:", true}, {"Password =  ", true}, {"PASSWORD:\t\r\n", true}, {"pa\u017f\u017fword:", true},
		{"to\u212aen=", true}, {"api-key :\v", true}, {"hasło:\u00a0", true}, {"x: secret=\u0085", true},
		{"password: value", false}, {"password:\x1b[0m", false}, {"password:\xff", false}, {"password", false},
		{"", false}, {" \t ", false}, {":", false}, {"=", false}, {"passwordx:", false}, {"mypassword:", true}, {"user:", false},
	} {
		if got := emptySecretLabel([]byte(c.in)); got != c.want {
			t.Errorf("emptySecretLabel(%q) = %v, want %v", c.in, got, c.want)
		}
		prefilterOff = true
		ref := emptySecretLabel([]byte(c.in))
		prefilterOff = false
		if ref != c.want {
			t.Errorf("reference(%q) = %v, want %v", c.in, ref, c.want)
		}
	}
}
