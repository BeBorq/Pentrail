package view

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The timeline shows each command in two explicit parts (typed by the user /
// printed by the terminal) and links its findings to the graph; the graph's
// detail panel shows the commands of an element. xref.js maps extracted
// entities to graph node IDs; this test checks that mapping against the real
// /api/graph and /api/entities of a synthetic database (contract with
// internal/store/graph.go), and runs xref.test.cjs.
func TestTimelineGraphCrossReference(t *testing.T) {
	page := string(indexHTML)
	for _, want := range []string{`<script src="/xref.js"></script>`,
		"Command — typed by the user", "Terminal output — printed by the programs",
		"showInGraph(pentrailXref.nodeIds(", "if(pendingCmd!=null)", "if(pendingNodes)",
		"pentrailXref.commandHTML(c,helpers,", "pentrailXref.commandIndex(e.data,edges)", "if(activeView!=='graph')leaveGraph();", "data-timeline="} {
		if !strings.Contains(page, want) {
			t.Fatalf("index.html lacks %q", want)
		}
	}
	if len(xrefJS) == 0 {
		t.Fatal("xref.js not embedded")
	}

	st := synthDB(t, synthPath(t.TempDir(), "xref.db"), nil)
	defer st.Close()
	ss, err := st.ListSessions()
	if err != nil || len(ss) == 0 {
		t.Fatalf("sessions: %v", err)
	}
	sid := ss[0].ID
	for _, e := range []struct {
		cmd             int
		typ, value, det string
	}{
		{2, "host", "192.0.2.10", ""},
		{0, "host", "192.0.2.10", ""},
		{2, "port", "192.0.2.10:22/tcp", `{"host":"192.0.2.10","service":"ssh"}`},
		{2, "port", "192.0.2.11:80/tcp", `{"host":"192.0.2.11"}`}, // host only implied
		{0, "hostname", "www.synth.test", `{"host":"192.0.2.10"}`},
		{1, "domain", "www.synth.test", ""}, // shown as the host name
		{1, "domain", "synth.test", ""},
		{2, "url", "https://www.synth.test/a?b=1", ""},
		{2, "endpoint", "https://www.synth.test/api", ""},
		{1, "email", "admin@synth.test", ""},
		{2, "finding", "CVE-0000-0001", `{"template":"t-1","host":"192.0.2.10","matched":"https://www.synth.test/a"}`},
		// Equivalent spellings in later commands (store: canonicalGraphHost links
		// relationships to the existing element; the element keeps its spelling).
		{0, "host", "2001:db8::1", ""},
		{2, "port", "[2001:DB8:0:0::1]:443/tcp", `{"host":"2001:DB8:0:0::1"}`},
		{1, "hostname", "Mail.Synth.Test", `{"host":"192.0.2.10"}`},
		{2, "url", "https://MAIL.SYNTH.TEST./login", ""},
		{2, "email", "ops@mail.synth.test.", ""},
		// A host name seen with a different address per command (04BI), the same
		// relationship seen again (the graph edge keeps only the first command),
		// and a standalone different spelling of an existing address.
		{0, "hostname", "rotating.example.test", `{"host":"192.0.2.1"}`},
		{2, "hostname", "rotating.example.test", `{"host":"192.0.2.2"}`},
		{0, "hostname", "stable.example.test", `{"host":"192.0.2.20"}`},
		{1, "hostname", "stable.example.test", `{"host":"192.0.2.20"}`},
		{2, "hostname", "stable.example.test", `{"host":"192.0.2.20"}`},
		{1, "host", "2001:DB8::0:1", ""},
	} {
		_, err := st.DB().Exec(`INSERT INTO entities(session_id,type,value,confidence,source_command_id,source_offset,tool,extractor,details,obs_key)
			VALUES(?,?,?,'high',(SELECT id FROM commands WHERE session_id=? AND cmd_index=?),0,'synthetic','test',?,?)`,
			sid, e.typ, e.value, sid, e.cmd, e.det, fmt.Sprintf("%s|%s|%d", e.typ, e.value, e.cmd))
		if err != nil {
			t.Fatal(err)
		}
	}
	const tok = "synthetic-xref-token"
	srv := serveSynth(t, st, tok)
	get := func(path string, auth bool) (int, []byte) {
		u := srv.URL + path
		if auth {
			u += map[bool]string{true: "&", false: "?"}[strings.Contains(path, "?")] + "t=" + tok
		}
		r, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}
	if code, _ := get("/xref.js", false); code != http.StatusUnauthorized {
		t.Fatalf("/xref.js without the token: %d", code)
	}
	if code, body := get("/xref.js", true); code != 200 || string(body) != string(xrefJS) {
		t.Fatalf("/xref.js: %d", code)
	}
	dir := t.TempDir()
	for name, path := range map[string]string{"graph.json": "/api/graph", "entities.json": "/api/entities", "commands.json": "/api/commands"} {
		code, body := get(fmt.Sprintf("%s?session=%d", path, sid), true)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Expected commands per element: "recorded" (its own value was extracted
	// from that command) or "related" (an element extracted there names it).
	expected := map[string][]string{
		"host:192.0.2.1":                     {"0:related"},
		"host:192.0.2.2":                     {"2:related"},
		"hostname:rotating.example.test":     {"0:recorded", "2:recorded"},
		"host:192.0.2.20":                    {"0:related", "1:related", "2:related"},
		"hostname:stable.example.test":       {"0:recorded", "1:recorded", "2:recorded"},
		"host:2001:db8::1":                   {"0:recorded", "2:related"},
		"host:2001:DB8::0:1":                 {"1:recorded"},
		"host:2001:DB8:0:0::1":               {"2:related"},
		"hostname:Mail.Synth.Test":           {"1:recorded", "2:related"},
		"host:192.0.2.10":                    {"0:recorded", "1:related", "2:recorded"},
		"host:192.0.2.11":                    {"2:related"},
		"port:[2001:DB8:0:0::1]:443/tcp":     {"2:recorded"},
		"url:https://MAIL.SYNTH.TEST./login": {"2:recorded"},
	}
	// canonicalGraphHost of internal/store/graph.go (netip.Addr.String, else
	// lower case without one trailing dot): the oracle for xref.canonicalHost.
	canon := map[string]string{}
	for _, h := range []string{"192.0.2.1", "01.2.3.4", "2001:DB8:0:0::1", "2001:db8:0:0:1:0:0:1", "1:0:0:1:0:0:0:1", "::FFFF:C000:0201",
		"::ffff:192.0.2.1", "::1.2.3.4", "fe80::1%Eth0", "::", "1::", "::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:1.2.3.4", "1::2::3",
		"WWW.Example.TEST.", "1.2.3.4%x", "2001:db8::", "0:0:0:0:0:ffff:1.2.3.4", "2001:0db8:0000:0000:0000:ff00:0042:8329", "a..", "::ffff:1.2.3"} {
		if a, err := netip.ParseAddr(h); err == nil {
			canon[h] = a.String()
		} else {
			canon[h] = strings.ToLower(strings.TrimSuffix(h, "."))
		}
	}
	for name, v := range map[string]any{"expected.json": expected, "canonical.json": canon} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: xref.contract.cjs and xref.test.cjs not run")
	}
	out, err := exec.Command(node, "xref.contract.cjs", dir).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS xref contract") {
		t.Fatalf("xref.contract.cjs: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
	out, err = exec.Command(node, "xref.test.cjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS xref 10") {
		t.Fatalf("xref.test.cjs: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
