package store

import (
	"strings"
	"testing"
)

// Synthetic, database-free probe of the graph's existing-node lookup.
// Equivalent spellings must link without rewriting the recorded node ID;
// a scoped address on another interface must remain a different endpoint.
func TestGraphEquivalentHostSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, kind, node, query string
		match                   bool
	}{
		{"ipv6_case", "host", "2001:DB8::A", "2001:db8::a", true},
		{"ipv6_expanded", "host", "2001:0db8:0000:0000:0000:0000:0000:000a", "2001:db8::a", true},
		{"ipv6_compressed", "host", "2001:db8::a", "2001:0DB8:0:0:0:0:0:A", true},
		{"dns_hostname_case", "hostname", "Example.TEST", "example.test", true},
		{"dns_domain_dot", "domain", "Example.TEST.", "example.test", true},
		{"scoped_same_interface", "host", "fe80::1%Ethernet", "fe80:0:0:0:0:0:0:1%Ethernet", true},
		{"scoped_other_interface", "host", "fe80::1%Ethernet", "fe80::1%ethernet", false},
		{"different_ipv6", "host", "2001:db8::a", "2001:db8::b", false},
		{"mapped_ipv6_equivalent", "host", "::ffff:c000:201", "::ffff:192.0.2.1", true},
		{"mapped_ipv6_not_ipv4", "host", "::ffff:c000:201", "192.0.2.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.kind + ":" + tc.node
			nodes := map[string]*GraphNode{id: {ID: id, Type: tc.kind, Label: tc.node}}
			var edges []GraphEdge
			add := func(a, b, typ, conf string, cmd int64) {
				edges = append(edges, GraphEdge{Source: a, Target: b, Type: typ})
			}
			linkToHostOrDomain(graphHostLookup(nodes, []string{id}), add, "url:synthetic", tc.query, "on", "high", 1)
			if tc.match {
				if len(edges) != 1 || edges[0].Target != id {
					t.Fatalf("equivalent host lost relation: node=%q query=%q edges=%+v", tc.node, tc.query, edges)
				}
			} else if len(edges) != 0 {
				t.Fatalf("distinct host gained relation: %+v", edges)
			}
		})
	}
}

func TestGraphHostAliasChoiceIsStable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		order       []string
		query, want string
	}{
		{"existing_canonical", []string{"host:2001:DB8::A", "host:2001:db8::a"}, "2001:0db8:0:0:0:0:0:a", "host:2001:db8::a"},
		{"first_recorded", []string{"host:2001:0DB8:0:0:0:0:0:A", "host:2001:DB8::A"}, "2001:db8::a", "host:2001:0DB8:0:0:0:0:0:A"},
		{"host_priority", []string{"domain:example.test", "hostname:Example.TEST", "host:EXAMPLE.TEST"}, "example.test", "host:EXAMPLE.TEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := map[string]*GraphNode{}
			for _, id := range tc.order {
				kind, value, _ := strings.Cut(id, ":")
				nodes[id] = &GraphNode{ID: id, Type: kind, Label: value}
			}
			for attempt := 0; attempt < 20; attempt++ {
				lookup := graphHostLookup(nodes, tc.order)
				var target string
				linkToHostOrDomain(lookup, func(_, b, _, _ string, _ int64) { target = b }, "url:synthetic", tc.query, "on", "high", 1)
				if target != tc.want {
					t.Fatalf("target=%q want=%q", target, tc.want)
				}
				if len(nodes) != len(tc.order) {
					t.Fatal("lookup inserted alias nodes into recorded graph")
				}
			}
		})
	}
}
