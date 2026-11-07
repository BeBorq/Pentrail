package store

import (
	"strings"
	"testing"
)

func TestGraphURLAuthority(t *testing.T) {
	for _, tc := range []struct{ input, host, label string }{
		{"https://[2001:db8::1]:8443/a", "2001:db8::1", "[2001:db8::1]:8443/a"},
		{"http://alice:synthetic-secret@[::1]/", "::1", "[::1]/"},
		{"https://alice:synthetic-secret@example.test:443/a", "example.test", "example.test:443/a"},
		{"example.test/a", "example.test", "example.test/a"},
		{"https://192.0.2.1/a", "192.0.2.1", "192.0.2.1/a"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := urlHost(tc.input); got != tc.host {
				t.Errorf("host = %q, want %q", got, tc.host)
			}
			if got := shortURL(tc.input); got != tc.label {
				t.Errorf("label = %q, want %q", got, tc.label)
			}
		})
	}
	// A malformed authority must not fall back to displaying its credentials.
	bad := "https://alice:synthetic-secret@[broken/a"
	if urlHost(bad) != "" || strings.Contains(shortURL(bad), "alice") || strings.Contains(shortURL(bad), "synthetic-secret") {
		t.Fatal("malformed URL exposes userinfo or invents a host")
	}
}

func TestGraphIPv6PortLabel(t *testing.T) {
	for _, value := range []string{"[2001:db8::1]:443/tcp", "2001:db8::1:443/tcp", "192.0.2.1:443/tcp", "443/tcp"} {
		if got := portLabel(value, map[string]string{"service": "https", "product": "synthetic"}); got != "443/tcp https synthetic" {
			t.Errorf("%q label = %q", value, got)
		}
	}
}

func TestGraphIPv6URLLinksHost(t *testing.T) {
	st := openTemp(t)
	insertEntity(t, st, "host", "2001:db8::1", "high", "", "ipv6-host", 0)
	insertEntity(t, st, "url", "https://alice:synthetic-secret@[2001:db8::1]:8443/a", "high", "", "ipv6-url", 1)
	g, err := st.BuildGraph(1)
	if err != nil {
		t.Fatal(err)
	}
	urlID := ""
	for _, n := range g.Nodes {
		if n.Type == "url" {
			urlID = n.ID
			if n.Label != "[2001:db8::1]:8443/a" {
				t.Fatalf("URL label = %q", n.Label)
			}
		}
	}
	for _, e := range g.Edges {
		if urlID != "" && e.Source == urlID && e.Target == "host:2001:db8::1" && e.Type == "on" {
			return
		}
	}
	t.Fatalf("missing IPv6 URL -> host edge: %+v", g.Edges)
}
