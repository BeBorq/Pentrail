//go:build linux

package capture

import (
	"encoding/base64"
	"testing"
)

// Authenticated markers are acted on; markers with a wrong token, and bare
// OSC 133 that untrusted target output could emit, are ignored.
func TestParserRejectsForgedMarkers(t *testing.T) {
	const tok = "secrettoken"
	const esc, bel = "\x1b]", "\x07"
	cmd := base64.StdEncoding.EncodeToString([]byte("echo hi"))

	var got []CommandEvent
	p := NewParser(tok, func(ev CommandEvent) { got = append(got, ev) }, nil, nil)
	p.Feed([]byte(
		esc+"697;"+tok+";CWD;/tmp"+bel+
			esc+"697;"+tok+";CMD;"+cmd+bel+
			esc+"697;"+tok+";C"+bel+
			"hi\r\n"+
			esc+"697;"+tok+";D;0"+bel), 0)
	if len(got) != 1 {
		t.Fatalf("valid markers: got %d commands, want 1", len(got))
	}
	if got[0].Command != "echo hi" || got[0].ExitCode != 0 {
		t.Fatalf("bad event: %+v", got[0])
	}

	var got2 []CommandEvent
	p2 := NewParser(tok, func(ev CommandEvent) { got2 = append(got2, ev) }, nil, nil)
	p2.Feed([]byte(
		esc+"697;WRONGTOKEN;CMD;"+cmd+bel+
			esc+"697;WRONGTOKEN;C"+bel+
			"evil\r\n"+
			esc+"697;WRONGTOKEN;D;0"+bel+
			esc+"133;D;0"+bel), 0)
	if len(got2) != 0 {
		t.Fatalf("forged markers produced %d commands, want 0", len(got2))
	}
}

// ART announces an artifact; FIN (emitted by the wrapper only after the tool
// exits) is what the importer gates completion on. Both must carry the token,
// so target output cannot forge a premature "finished" signal for a file that
// is still being written.
func TestParserArtifactFinalizeDispatch(t *testing.T) {
	const tok = "secrettoken"
	const esc, bel = "\x1b]", "\x07"
	cmd := base64.StdEncoding.EncodeToString([]byte("nmap -sV t"))

	type art struct {
		tool, path string
		idx        int64
	}
	var arts []art
	var fins []string
	p := NewParser(tok,
		func(CommandEvent) {},
		func(tool, path string, idx int64) { arts = append(arts, art{tool, path, idx}) },
		func(path string) { fins = append(fins, path) })

	p.Feed([]byte(
		esc+"697;"+tok+";CMD;"+cmd+bel+
			esc+"697;"+tok+";C"+bel+
			esc+"697;"+tok+";ART;nmap;/art/nmap-1.xml"+bel+
			"scan output\r\n"+
			// forged FIN from the scanned target: wrong token -> must be ignored
			esc+"697;WRONGTOKEN;FIN;/art/nmap-1.xml"+bel+
			esc+"697;"+tok+";FIN;/art/nmap-1.xml"+bel+
			esc+"697;"+tok+";D;0"+bel), 0)

	if len(arts) != 1 || arts[0].tool != "nmap" || arts[0].path != "/art/nmap-1.xml" {
		t.Fatalf("ART dispatch: got %+v, want one nmap /art/nmap-1.xml", arts)
	}
	if len(fins) != 1 || fins[0] != "/art/nmap-1.xml" {
		t.Fatalf("FIN dispatch: got %v, want exactly one authenticated finalize", fins)
	}
}
