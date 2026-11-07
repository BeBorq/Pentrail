package report

import (
	"bytes"
	"encoding/json"
	"github.com/BeBorq/Pentrail/internal/store"
	"testing"
)

func TestReportFormatsMaskSecretsAndNeutralizeCSV(t *testing.T) {
	b := Bundle{Commands: []store.CommandInfo{{Command: "tool --password reportSecret"}}, Entities: []store.EntityRow{{Type: "finding", Value: "=WEBSERVICE(\"bad\")", Details: `{"password":"reportSecret"}`}}}
	j, e := JSON(b)
	if e != nil || !json.Valid(j) || bytes.Contains(j, []byte("reportSecret")) {
		t.Fatal(string(j), e)
	}
	h, e := HTML(b)
	if e != nil || bytes.Contains(h, []byte("reportSecret")) {
		t.Fatal(string(h), e)
	}
	c, e := CSV(b)
	if e != nil || bytes.Contains(c, []byte("reportSecret")) || !bytes.Contains(c, []byte("'=WEBSERVICE")) {
		t.Fatal(string(c), e)
	}
}
