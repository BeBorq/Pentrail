package store

import (
	"reflect"
	"testing"
)

func TestGraphEquivalentHostIntegration(t *testing.T) {
	for _, tc := range []struct {
		name, kind, host, url string
		match                 bool
	}{
		{"ipv6_case", "host", "2001:DB8::A", "https://[2001:db8::a]/a", true},
		{"ipv6_expanded", "host", "2001:0db8:0:0:0:0:0:a", "https://[2001:db8::a]/a", true},
		{"dns_case", "hostname", "Example.TEST", "https://example.test/a", true},
		{"dns_dot", "domain", "Example.TEST.", "https://example.test/a", true},
		{"scope_same", "host", "fe80:0:0:0:0:0:0:1%Ethernet", "http://[fe80::1%25Ethernet]/a", true},
		{"scope_different", "host", "fe80::1%Ethernet", "http://[fe80::1%25ethernet]/a", false},
		{"address_different", "host", "2001:db8::a", "https://[2001:db8::b]/a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := openTemp(t)
			insertEntity(t, st, tc.kind, tc.host, "high", "", "recorded-host", 0)
			insertEntity(t, st, "url", tc.url, "high", "", "recorded-url", 1)
			before, err := st.ListEntityRows(1)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				graph, err := st.BuildGraph(1)
				if err != nil {
					t.Fatal(err)
				}
				if len(graph.Nodes) != 2 {
					t.Fatalf("nodes rewritten or invented: %+v", graph.Nodes)
				}
				id := tc.kind + ":" + tc.host
				original := false
				for _, n := range graph.Nodes {
					if n.ID == id && n.Label == tc.host {
						original = true
					}
				}
				if !original {
					t.Fatal("original recorded host identity changed")
				}
				linked := false
				for _, e := range graph.Edges {
					if e.Source == "url:"+tc.url && e.Target == id && e.Type == "on" {
						linked = true
					}
				}
				if linked != tc.match {
					t.Fatalf("link=%v want=%v host=%q url=%q graph=%+v", linked, tc.match, tc.host, tc.url, graph)
				}
			}
			after, err := st.ListEntityRows(1)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("graph lookup changed stored evidence")
			}
		})
	}
}

func TestGraphEquivalentHostAllRelationships(t *testing.T) {
	st := openTemp(t)
	insertEntity(t, st, "host", "2001:0DB8:0:0:0:0:0:A", "high", "", "explicit-host", 0)
	insertEntity(t, st, "port", "[2001:db8::a]:443/tcp", "high", `{"host":"2001:db8::a","port":"443"}`, "port", 1)
	insertEntity(t, st, "hostname", "SVC.TEST", "high", `{"host":"2001:DB8::A"}`, "hostname", 2)
	insertEntity(t, st, "url", "https://[2001:db8::a]/a", "high", "", "url", 3)
	insertEntity(t, st, "finding", "synthetic-finding", "high", `{"host":"2001:db8::a"}`, "finding", 4)
	before, err := st.ListEntityRows(1)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := st.BuildGraph(1)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range graph.Edges {
		if e.Type == "on" || e.Type == "resolves" || e.Type == "affects" {
			count++
			if e.Target != "host:2001:db8::a" {
				t.Errorf("equivalent host split its relationships: %+v", e)
			}
		}
	}
	if count != 4 {
		t.Fatalf("expected four relationships, got %+v", graph.Edges)
	}
	after, err := st.ListEntityRows(1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("graph lookup changed stored evidence")
	}
}
