package redact

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every argument of an authenticated 697 marker is session metadata that is
// stored in raw_chunks. Before the fix only the token and the decoded CMD were
// sanitized: a CWD, ART, FIN or unknown verb carried a credential verbatim.
func TestOSC697ArgumentsAreSanitized(t *testing.T) {
	cases := []struct{ name, in, secret string }{
		{"cwd", "\x1b]697;audit-token;CWD;C:/password=SyntheticOSCSecret\x07\n", "SyntheticOSCSecret"},
		{"cwd-st", "\x1b]697;audit-token;CWD;/srv/token=StTerminated99\x1b\\\n", "StTerminated99"},
		{"art", "\x1b]697;audit-token;ART;nmap;/tmp/api_key=ArtSecret77/x.xml\x07\n", "ArtSecret77"},
		{"fin", "\x1b]697;audit-token;FIN;/tmp/passwd=FinSecret55\x07\n", "FinSecret55"},
		{"unknown-verb", "\x1b]697;audit-token;XYZ;password=UnknownVerb42\x07\n", "UnknownVerb42"},
		{"verb-only", "\x1b]697;audit-token;secret=OnlyVerb31\x07\n", "OnlyVerb31"},
		{"exit", "\x1b]697;audit-token;D;password=DSecret12\x07\n", "DSecret12"},
	}
	for _, c := range cases {
		out, _ := Text([]byte(c.in))
		if len(out) != len(c.in) {
			t.Fatalf("%s: length changed %d -> %d", c.name, len(c.in), len(out))
		}
		if bytes.Contains(out, []byte(c.secret)) {
			t.Fatalf("%s: secret stored: %q", c.name, out)
		}
		if bytes.Contains(out, []byte("audit-token")) {
			t.Fatalf("%s: marker token stored: %q", c.name, out)
		}
	}
}

// Ordinary metadata (Unicode paths, verbs, exit codes) must survive untouched.
func TestOSC697PreservesOrdinaryMetadata(t *testing.T) {
	in := "\x1b]697;tok;CWD;/home/zażółć/gęślą jaźń\x07\x1b]697;tok;D;0\x07\x1b]697;tok;A\x07prompt$ \n"
	out, n := Text([]byte(in))
	want := strings.ReplaceAll(in, "tok", "***")
	if string(out) != want {
		t.Fatalf("ordinary metadata changed:\n got %q\nwant %q", out, want)
	}
	if n != 9 || !utf8.Valid(out) {
		t.Fatalf("changed=%d valid=%v", n, utf8.Valid(out))
	}
}

// The PTY delivers markers in arbitrary pieces; the stored result must not
// depend on where the reads split, including a flush (Seal) inside a marker.
func TestOSC697SplitAcrossReadsAndFlush(t *testing.T) {
	in := []byte("ls\r\n\x1b]697;audit-token;CWD;C:/password=SyntheticOSCSecret\x07out\r\n")
	want, _ := Text(in)
	var s Stream
	var got []byte
	for _, b := range in {
		got = append(got, s.Feed([]byte{b})...)
	}
	got = append(got, s.Finish()...)
	if !bytes.Equal(got, want) {
		t.Fatalf("byte-by-byte differs:\n got %q\nwant %q", got, want)
	}
	for cut := 1; cut < len(in); cut++ {
		var st Stream
		out := st.Feed(in[:cut])
		out = append(out, st.Seal()...) // `pentrail flush` / pause boundary
		out = append(out, st.Feed(in[cut:])...)
		out = append(out, st.Finish()...)
		if len(out) != len(in) {
			t.Fatalf("cut %d: length %d != %d", cut, len(out), len(in))
		}
		if bytes.Contains(out, []byte("SyntheticOSCSecret")) || bytes.Contains(out, []byte("audit-token")) {
			t.Fatalf("cut %d: leaked across seal: %q", cut, out)
		}
	}
}

// Records written by masked-v2 kept marker arguments verbatim. The read path
// must protect them without rewriting the stored history.
func TestLegacyMaskedV2MarkerArgumentsProtectedOnRead(t *testing.T) {
	stored := []byte("a\r\n\x1b]697;***********;CWD;C:/password=SyntheticOSCSecret\x07b\r\n\x1b]697;***;CWD;/home/zażółć\x07c\r\n")
	out := ProtectLegacyMarkers(stored)
	if len(out) != len(stored) {
		t.Fatalf("length changed")
	}
	if bytes.Contains(out, []byte("SyntheticOSCSecret")) {
		t.Fatalf("legacy secret visible: %q", out)
	}
	if !bytes.Contains(out, []byte("/home/zażółć")) {
		t.Fatalf("ordinary legacy path damaged: %q", out)
	}
	// An unterminated marker at the end of the window fails closed.
	cut := []byte("x\x1b]697;***;CWD;C:/password=Half")
	if bytes.Contains(ProtectLegacyMarkers(cut), []byte("Half")) {
		t.Fatal("unterminated legacy marker not masked")
	}
}
