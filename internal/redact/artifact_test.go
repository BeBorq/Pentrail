package redact

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"testing"
)

func TestLargeNmapXMLRetainsStructureAndMasksFields(t *testing.T) {
	var input bytes.Buffer
	input.WriteString(`<nmaprun>`)
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&input, `<host><address addr="192.0.2.%d" addrtype="ipv4"/><script id="audit" output="password='XMLSecret'"/><table key="password"><elem>XMLSecret</elem></table></host>`, i%255)
	}
	input.WriteString(`</nmaprun>`)
	out, e := Artifact("nmap", input.Bytes())
	if e != nil || bytes.Contains(out, []byte("XMLSecret")) || bytes.Count(out, []byte(`<host>`)) != 1200 {
		t.Fatal("lost XML structure", e)
	}
	var document interface{}
	if e = xml.Unmarshal(out, &document); e != nil {
		t.Fatal(e)
	}
}

// Interrupted tools leave damaged files. Sanitizing must not fail (that broke
// ingest permanently); the damaged remainder is masked, the valid part kept.
func TestArtifactPartialFailsClosed(t *testing.T) {
	nmap := []byte(`<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/></host><host><script id="x" output="password=hunter2`)
	out, partial, err := ArtifactPartial("nmap", nmap)
	if err != nil || !partial {
		t.Fatalf("nmap: partial=%v err=%v", partial, err)
	}
	if !bytes.Contains(out, []byte(`addr="10.0.0.5"`)) {
		t.Fatalf("valid prefix lost: %s", out)
	}
	if bytes.Contains(out, []byte("hunter2")) || len(out) == 0 {
		t.Fatalf("damaged tail not masked: %s", out)
	}

	nuclei := []byte("{\"template-id\":\"a\",\"host\":\"h\",\"matched-at\":\"m\"}\n{\"template-id\":\"b\",\"token\":\"sekret")
	out, partial, err = ArtifactPartial("nuclei", nuclei)
	if err != nil || !partial || bytes.Contains(out, []byte("sekret")) || !bytes.Contains(out, []byte(`"template-id":"a"`)) {
		t.Fatalf("nuclei: partial=%v err=%v out=%s", partial, err, out)
	}

	// Nothing salvageable: an error, so the caller keeps the original on disk.
	if _, _, err = ArtifactPartial("ffuf", []byte(`{"results":[{"url":"http://x/?password=hunter2"`)); err == nil {
		t.Fatal("unsalvageable ffuf accepted")
	}
	if _, _, err = ArtifactPartial("nmap", []byte(`<unfinished`)); err == nil {
		t.Fatal("unsalvageable nmap accepted")
	}

	out, partial, err = ArtifactPartial("nmap", []byte(`<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/></host></nmaprun>`))
	if err != nil || partial || !bytes.Contains(out, []byte("1.2.3.4")) {
		t.Fatalf("complete nmap flagged partial: %v %v %s", partial, err, out)
	}
}

// Codex audit: JSON() decoded only the first document. Two concatenated
// documents (or a valid document plus a damaged tail) were accepted as the
// first one; the importer stored that and deleted the whole original.
func TestJSONRequiresExactlyOneDocument(t *testing.T) {
	for _, in := range []string{
		`{"a":1}{"b":2}`,
		`{"a":1} {"b":2}`,
		`{"results":[]}` + "\n" + `{"results":[{"url":"http://x"}]}`,
		`{"a":1}garbage`,
		`{"a":1}]`,
	} {
		if _, e := JSON([]byte(in)); e == nil {
			t.Fatalf("accepted %q as one document", in)
		}
		if _, _, e := ArtifactPartial("ffuf", []byte(in)); e == nil {
			t.Fatalf("ffuf accepted %q", in)
		}
	}
	for _, in := range []string{`{"a":1}`, "{\"a\":1}\n", " {\"a\":1} \r\n\t"} {
		if _, e := JSON([]byte(in)); e != nil {
			t.Fatalf("rejected a single document %q: %v", in, e)
		}
	}
	// one JSONL record holding two documents is damaged, not two results
	out, partial, e := ArtifactPartial("nuclei", []byte("{\"template-id\":\"a\"}\n{\"template-id\":\"b\"}{\"template-id\":\"c\"}\n"))
	if e != nil || !partial || bytes.Contains(out, []byte(`"c"`)) || !bytes.Contains(out, []byte(`"a"`)) {
		t.Fatalf("nuclei: partial=%v err=%v out=%s", partial, e, out)
	}
}
