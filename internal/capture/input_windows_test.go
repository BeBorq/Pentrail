//go:build windows

package capture

import (
	"bytes"
	"testing"
)

func TestWindowsCMDInputDecoding(t *testing.T) {
	var d winInputDecoder
	wire := []byte("\x1b[65;30;97;1;0;1_\x1b[65;30;97;0;0;1_\x1b[0;0;380;1;0;1_\x1b[13;28;13;1;0;1_")
	var all []byte
	for _, b := range wire {
		all = append(all, d.Decode([]byte{b})...)
	}
	if !bytes.Equal(all, []byte("aż\r")) {
		t.Fatalf("decoded %q", all)
	}
	if !bytes.Contains(d.Decode([]byte("\x1b[38;72;0;1;0;1_")), []byte{27}) {
		t.Fatal("history navigation treated as exact text")
	}
}
