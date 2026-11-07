package report

import (
	"bytes"
	"testing"
)

func TestConPTYMappingLimitationVisibleInDeliverables(t *testing.T) {
	b := Bundle{OutputMapping: "conpty-session"}
	j, e := JSON(b)
	if e != nil || !bytes.Contains(j, []byte(`"output_mapping": "conpty-session"`)) {
		t.Fatal(string(j), e)
	}
	h, e := HTML(b)
	if e != nil || !bytes.Contains(h, []byte("Windows ConPTY")) {
		t.Fatal("mapping warning missing from HTML", e)
	}
	j, e = JSON(Bundle{})
	if e != nil || bytes.Contains(j, []byte("output_mapping")) {
		t.Fatal("Windows limitation incorrectly applied to other sessions", e)
	}
}
