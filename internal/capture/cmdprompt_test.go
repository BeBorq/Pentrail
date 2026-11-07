package capture

import (
	"strings"
	"testing"
)

func TestCMDPrompt(t *testing.T) {
	for _, c := range []struct{ user, want string }{
		{"", "$E]697;tok;A\a$E]697;tok;P;$P$G\a$P$G"},
		{"$P$G", "$E]697;tok;A\a$E]697;tok;P;$P$G\a$P$G"},
		{"$E[32m$P$G$E[0m ", "$E]697;tok;A\a$E]697;tok;P;$P$G \a$E[32m$P$G$E[0m "},
		{"[$T] $P$G", "$E]697;tok;A\a$E]697;tok;P;[$T] $P$G\a[$T] $P$G"},
		{"$P$_$G", "$E]697;tok;A\a$P$_$G"},             // two lines: no text
		{"$E]0;x\a$P$G", "$E]697;tok;A\a$E]0;x\a$P$G"}, // other escape: no text
	} {
		if got := CMDPrompt("tok", c.user); got != c.want {
			t.Errorf("CMDPrompt(%q) = %q, want %q", c.user, got, c.want)
		}
	}
}

// With the text in the marker, any prompt shape is found on screen; output
// that merely resembles a default prompt is not taken for one.
func TestCMDCustomPromptWithMarkerText(t *testing.T) {
	h := newSeg(t)
	mark := "\x1b]697;" + segTok + ";A\x07\x1b]697;" + segTok + ";P;[12:00] work>\x07"
	h.out(mark+"[12:00] work>", false)
	h.in("dir\r", false)
	// ConPTY order: echo, the next marker early, then output and prompt
	h.out("dir\r\n"+mark+"C:\\fake>not a prompt\r\nfile.txt\r\n\r\n[12:00] work>", false)
	h.seg.Close(h.off)
	h.want("dir")
	c := h.rows[0]
	stream := h.stream.String()
	if out := stream[c.OutStartOff:c.OutEndOff]; !strings.Contains(out, "file.txt") || !strings.Contains(out, "C:\\fake>") {
		t.Fatalf("output range %q", out)
	}
}
