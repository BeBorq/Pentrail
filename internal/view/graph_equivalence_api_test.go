package view

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeBorq/Pentrail/internal/store"
)

func TestGraphEquivalentHostAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "graph.db"), []byte("synthetic-graph-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.StartSession("bash", "synthetic", "test")
	if err != nil {
		t.Fatal(err)
	}
	const host = "2001:0DB8:0:0:0:0:0:A"
	const legacyURL = "https://alice:synthetic-view-secret@[2001:db8::a]/a"
	for _, row := range []struct{ kind, value string }{{"host", host}, {"url", legacyURL}} {
		_, err = st.DB().Exec(`INSERT INTO entities(session_id,type,value,confidence,tool,extractor,obs_key) VALUES(?,?,?,'high','synthetic','test',?)`, id, row.kind, row.value, row.kind)
		if err != nil {
			t.Fatal(err)
		}
	}
	server := New(st)
	server.token = "synthetic-token"
	handler := server.guard(server.handleGraph)
	for _, authorized := range []bool{false, true} {
		query := fmt.Sprintf("http://127.0.0.1/api/graph?session=%d", id)
		if authorized {
			query += "&t=synthetic-token"
		}
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, query, nil))
		if !authorized {
			if response.Code != http.StatusUnauthorized {
				t.Fatal("graph exposed without token")
			}
			continue
		}
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("code=%d headers=%v", response.Code, response.Header())
		}
		if strings.Contains(response.Body.String(), "synthetic-view-secret") {
			t.Fatal("legacy credential leaked through graph JSON")
		}
		var graph store.Graph
		if err = json.Unmarshal(response.Body.Bytes(), &graph); err != nil {
			t.Fatal(err)
		}
		nodes := map[string]bool{}
		for _, n := range graph.Nodes {
			nodes[n.ID] = true
		}
		if !nodes["host:"+host] || len(graph.Nodes) != 2 || len(graph.Edges) != 1 {
			t.Fatalf("equivalent address lost its relationship or original identity: %+v", graph)
		}
		edge := graph.Edges[0]
		if edge.Target != "host:"+host || edge.Type != "on" || !nodes[edge.Source] {
			t.Fatalf("JSON masking broke graph references: %+v", graph)
		}
	}
}
