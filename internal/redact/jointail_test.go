package redact

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// Codex 04AB: the join's tail scan (jointail.go) against the references.

// jtValue: n random characters of a secret-looking value (no spaces).
func jtValue(r *rand.Rand, n int) string {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-.!/"
	b := make([]byte, n)
	for i := range b {
		b[i] = abc[r.Intn(len(abc))]
	}
	return string(b)
}

// jtPieces: fragments of rows as ConPTY prints them — the throughput test's
// trigger row, labels whose value follows on the next row, quoted values
// left open or closed across rows, every pattern's vocabulary, empty labels,
// PEM boundaries, non-ASCII text, OSC and CSI sequences.
func jtPieces(r *rand.Rand) []string {
	v := jtValue(r, 1+r.Intn(90))
	return []string{
		"net user admin: token=" + jtValue(r, 80), "net user admin ", "NET.exe user bob ", "token=", "token:", "Password: ", "password=",
		`password="` + v, `password="` + v + `"`, `'` + v, `"`, `'`, v, " " + v + " ", "api_key = ", "secret:", "hasło: ", "pwd=",
		"curl -u alice:" + v, "curl x ", " --user ", "wget.exe ", "cookie: " + v, "Set-Cookie:", "Authorization: Bearer " + v,
		"https://u:" + v + "@h/", "<password>" + v + "</password>", "<token x=1>", "</", "sshpass -p " + v, "mysql ", " -p", "--token " + v,
		"--password=", "ConvertTo-SecureString '" + v + "'", "identified by '", "with password \"", "password is " + v,
		"AKIA" + strings.ToUpper(jtValue(r, 16)), "eyJ" + v + "." + v + "." + v, "http://127.0.0.1:8080/?t=abc123",
		"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "żółć ", "\xff", "\x1b[1m", "\x1b[0m", "\x1b[3",
		"\x1b]0;title\x07", " ", "  ", "\t", ":", "=", "x", "user", "admin",
	}
}

func jtText(r *rand.Rand, n int) string {
	var sb strings.Builder
	for k := 0; k < n; k++ {
		p := jtPieces(r)
		sb.WriteString(p[r.Intn(len(p))])
	}
	return sb.String()
}

// The lemma the restart rests on: at every position s strictly inside a
// match of the full FindAll chain, the restart check says "maybe a partial
// match here" — with tailCheck always, with tailCheckNoQ whenever text[:s]
// has no quote. If it ever said "none" inside a real match, the tail scan
// could miss or shift that match.
func TestJoinTailCheckNeverMissesAMatch(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	inside, noq := 0, 0
	n := 6000
	if raceEnabled {
		n = 600
	}
	for c := 0; c < n; c++ {
		v := []byte(jtText(r, 2+r.Intn(10)))
		if !isASCII(v) {
			continue
		}
		rev := append([]byte(nil), v...)
		for a, b := 0, len(rev)-1; a < b; a, b = a+1, b-1 {
			rev[a], rev[b] = rev[b], rev[a]
		}
		fq := bytes.IndexAny(v, `"'`)
		if fq < 0 {
			fq = len(v)
		}
		for i, re := range patterns {
			for _, m := range re.FindAllSubmatchIndex(v, -1) {
				for s := m[0] + 1; s < m[1]; s++ {
					inside++
					x := rev[len(v)-1-s:]
					if !tailCheck[i].Match(x) {
						t.Fatalf("pattern %d: no partial match reported at %d inside match %v of %q", i, s, m[:2], v)
					}
					if s <= fq {
						noq++
						if !tailCheckNoQ[i].Match(x) {
							t.Fatalf("pattern %d (no quote before %d): no partial match reported inside match %v of %q", i, s, m[:2], v)
						}
					}
				}
			}
		}
	}
	if inside < 10000 || noq < 1000 {
		t.Fatalf("too few positions inside matches (%d, %d without quote): the generator does not exercise the patterns", inside, noq)
	}
	t.Logf("%d positions inside matches (%d without a quote before them): the check never said none", inside, noq)
}

// plainTail equals plain() at every index from its start index on, on
// generated texts, for many start indices; and the restart is really used.
func TestPlainTailEqualsPlain(t *testing.T) {
	r := rand.New(rand.NewSource(12))
	sc := new(scratch)
	cases, restarts, fallbacks := 0, 0, 0
	n := 4000
	if raceEnabled {
		n = 400
	}
	for c := 0; c < n; c++ {
		src := []byte(jtText(r, 3+r.Intn(30)))
		ref := append([]byte(nil), src...)
		plain(ref)
		found := litsFound(foldCanonAppend(nil, src))
		for k := 0; k < 6; k++ {
			from := r.Intn(len(src) + 1)
			if k == 0 {
				from = len(src) - min(len(src), r.Intn(140)) // a last row
			}
			dst := append([]byte(nil), src...)
			plainTail(dst, src, from, found, sc)
			if !bytes.Equal(dst[from:], ref[from:]) {
				t.Fatalf("plainTail from %d differs from plain:\n%q\n%q\n%q", from, src, dst[from:], ref[from:])
			}
			cases++
			if from > 0 && from < len(src) && isASCII(src) {
				rev := []byte(nil)
				for a := len(src) - 1; a >= 0; a-- {
					rev = append(rev, src[a])
				}
				fq := bytes.IndexAny(src, `"'`)
				if fq < 0 {
					fq = len(src)
				}
				for i := range patterns {
					if mayMatch(i, found) {
						if tailStart(i, src, rev, from, fq) > 0 {
							restarts++
						} else {
							fallbacks++
						}
					}
				}
			}
		}
	}
	if restarts < 1000 || fallbacks < 100 {
		t.Fatalf("restart used %d times, full scan %d times: not exercised", restarts, fallbacks)
	}
	t.Logf("%d (text, start) cases identical to plain(); per pattern: restart %d, full scan %d", cases, restarts, fallbacks)
}

// The Stream with the tail scan against the pre-04L code run with every
// pattern (feedRef, prefilterOff) on ConPTY-shaped streams: cursor-led rows
// built from jtPieces (labels at a row's end with the value on the next
// row, open quotes, repaints of the previous row's end, empty labels, PEM,
// OSC, non-ASCII, rows longer than the 4 KiB context), the throughput
// test's trigger rows, random batch boundaries; output, Changed and state
// (context, pending, nextSecretLine, pem, closedLine) after every batch.
func TestJoinTailStreamEqualsReference(t *testing.T) {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	trigger := func(i int) string {
		b := make([]byte, 80)
		for k := range b {
			j := i*120 + k
			b[k] = abc[(j*7+j/97)%len(abc)]
		}
		return "net user admin: token=" + string(b)
	}
	rows := 1500
	if raceEnabled {
		rows = 200
	}
	masked := 0
	for run := 0; run < 6; run++ {
		r := rand.New(rand.NewSource(int64(100 + run)))
		var text []byte
		prev := ""
		for k := 0; k < rows; k++ {
			var row string
			switch {
			case run == 0 || r.Intn(4) == 0:
				row = trigger(k) // the throughput test's rows
			case r.Intn(40) == 0:
				row = jtText(r, 60+r.Intn(80)) // longer than the context
			default:
				row = jtText(r, 1+r.Intn(6))
			}
			if n := r.Intn(24); r.Intn(4) == 0 && n > 0 && n <= len(prev) {
				row = prev[len(prev)-n:] + row // repaint of the previous row's end
			}
			prev = row
			if run == 0 || r.Intn(6) > 0 {
				text = append(text, fmt.Sprintf("\x1b[%d;1H", 1+r.Intn(30))...)
			}
			text = append(text, row...)
			text = append(text, "\r\n"...)
		}
		br := rand.New(rand.NewSource(int64(run)))
		var fastSt, refSt Stream
		var fast, ref []byte
		for i := 0; i < len(text); {
			n := min(len(text)-i, 1+br.Intn(8<<10))
			c := fastSt.Clone()
			fast = append(fast, c.Feed(text[i:i+n])...)
			fastSt = c
			prefilterOff = true
			c = refSt.Clone()
			ref = append(ref, c.feedRef(text[i:i+n])...)
			refSt = c
			prefilterOff = false
			if string(fastSt.context) != string(refSt.context) || string(fastSt.pending) != string(refSt.pending) ||
				fastSt.nextSecretLine != refSt.nextSecretLine || fastSt.pem != refSt.pem || fastSt.closedLine != refSt.closedLine ||
				fastSt.Changed != refSt.Changed || !bytes.Equal(fast, ref) {
				k := 0
				for k < len(fast) && k < len(ref) && fast[k] == ref[k] {
					k++
				}
				t.Fatalf("run %d: differs after byte %d (changed %d vs %d), output at %d: %q vs %q", run, i+n, fastSt.Changed, refSt.Changed,
					k, fast[k:min(len(fast), k+80)], ref[k:min(len(ref), k+80)])
			}
			i += n
		}
		fast = append(fast, fastSt.Finish()...)
		prefilterOff = true
		ref = append(ref, refSt.Finish()...)
		prefilterOff = false
		if !bytes.Equal(fast, ref) || fastSt.Changed != refSt.Changed {
			t.Fatalf("run %d: final output differs", run)
		}
		if refSt.Changed == 0 {
			t.Fatalf("run %d masked nothing", run)
		}
		masked += int(refSt.Changed)
	}
	t.Logf("6 streams of %d rows (run 0: only trigger rows), identical to the reference after every batch; %d bytes masked", rows, masked)
}

// Codex 04AE: the generated check sources (jointail_sources.go) are exactly
// what tailCheckSources builds from the current patterns. With
// PENTRAIL_REGEN_JOINTAIL=1 the file is rewritten instead.
func TestJoinTailCheckSourcesAreCurrent(t *testing.T) {
	var all, noq []string
	for _, re := range patterns {
		a, b := tailCheckSources(re)
		all, noq = append(all, a), append(noq, b)
	}
	if os.Getenv("PENTRAIL_REGEN_JOINTAIL") == "1" {
		var sb strings.Builder
		sb.WriteString("// Code generated by TestJoinTailCheckSourcesAreCurrent (PENTRAIL_REGEN_JOINTAIL=1); DO NOT EDIT.\n\npackage redact\n\n")
		for _, v := range []struct {
			name string
			src  []string
		}{{"tailCheckSrc", all}, {"tailCheckNoQSrc", noq}} {
			fmt.Fprintf(&sb, "var %s = []string{\n", v.name)
			for i, s := range v.src {
				fmt.Fprintf(&sb, "\t%q, // patterns[%d]\n", s, i)
			}
			sb.WriteString("}\n\n")
		}
		if err := os.WriteFile("jointail_sources.go", []byte(strings.TrimSuffix(sb.String(), "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("jointail_sources.go rewritten")
		return
	}
	for i := range patterns {
		if tailCheckSrc[i] != all[i] || tailCheckNoQSrc[i] != noq[i] {
			t.Fatalf("jointail_sources.go is stale for patterns[%d]: regenerate with PENTRAIL_REGEN_JOINTAIL=1", i)
		}
	}
}
