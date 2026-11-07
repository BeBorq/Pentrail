package redact

import (
	"bytes"
	"testing"
)

func TestConPTYWrappedPasswordLabel(t *testing.T) {
	for _, raw := range []string{"set \"P50R=PASSWORD\r\n\x1b[29;120HD='Synthetic50Secret'\"\r\npublic\r\n", "set \"P50R=PASSWOR\r\n\x1b[29;120HD='Synthetic50Secret'\"\r\npublic\r\n", "PASS\r\n\x1b[2;1HWORD='\r\n\x1b[3;1HSynthetic50Secret'\r\npublic\r\n"} {
		for split := 0; split <= len(raw); split++ {
			var s Stream
			out := s.Feed([]byte(raw[:split]))
			out = append(out, s.Feed([]byte(raw[split:]))...)
			out = append(out, s.Finish()...)
			if len(out) != len(raw) || bytes.Contains(out, []byte("Synthetic50Secret")) || !bytes.Contains(out, []byte("public")) {
				t.Fatalf("split %d: %q", split, out)
			}
		}
	}
}

func TestSealMetadataDoesNotHidePublicContinuation(t *testing.T) {
	var s Stream
	out := s.Feed([]byte("\x1b]697;abcdef;C\aPUBLIC_PART"))
	out = append(out, s.Seal()...)
	out = append(out, s.Feed([]byte("_DONE\n"))...)
	if !bytes.Contains(out, []byte("PUBLIC_PART_DONE")) || bytes.Contains(out, []byte("abcdef")) {
		t.Fatalf("%q", out)
	}
}
