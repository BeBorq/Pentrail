package extract

import (
	"strings"
	"testing"
)

func TestVTDoesNotBecomeDomainAndOffsetsRemainOriginal(t *testing.T) {
	raw := []byte("prefix \x1b[37m.Replace \x1b[32mhttps://api.example.test/path\x1b[0m \x1b]0;hidden.example.test\a 192.0.2.10")
	matches := Run(raw)
	urlFound, hostFound := false, false
	for _, m := range matches {
		if strings.Contains(m.Value, "37m") || strings.Contains(m.Value, "hidden.example") {
			t.Fatal(m)
		}
		if m.Kind == KindURL {
			urlFound = true
			if m.Offset != strings.Index(string(raw), "https://") {
				t.Fatal(m)
			}
		}
		if m.Kind == KindHost {
			hostFound = true
			if m.Offset != strings.Index(string(raw), "192.0.2.10") {
				t.Fatal(m)
			}
		}
	}
	if !urlFound || !hostFound {
		t.Fatal(matches)
	}
}
