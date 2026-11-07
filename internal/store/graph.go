package store

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
)

// Layer 4 input: a graph built from the entities of a session. Nodes are typed
// (host, port, hostname, domain, url, endpoint, email, finding); edges are typed
// and directed (the "correlations and relationships"). Every node keeps its provenance
// so the view can answer "where do I know this from".

type GraphNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Label      string            `json:"label"`
	Confidence string            `json:"confidence"`
	Tool       string            `json:"tool"`
	CmdIndex   int64             `json:"cmd_index"`
	Offset     int64             `json:"offset"`
	Details    map[string]string `json:"details,omitempty"`
}

type GraphEdge struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	CmdIndex   int64  `json:"cmd_index"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// BuildGraph derives nodes and typed edges from a session's entities.
func (s *Store) BuildGraph(sessionID int64) (Graph, error) {
	rows, err := s.ListEntityRows(sessionID)
	if err != nil {
		return Graph{}, err
	}

	// Pre-scan hostname values so a low-confidence regex "domain" with the same
	// name as a high-confidence "hostname" doesn't become a duplicate node,
	// regardless of row order.
	hostnameVals := map[string]bool{}
	for _, r := range rows {
		if r.Type == "hostname" {
			hostnameVals[r.Value] = true
		}
	}

	nodes := map[string]*GraphNode{}
	var order []string
	edgeSet := map[string]bool{}
	var edges []GraphEdge

	ensure := func(id, typ, label, conf, tool string, cmd, off int64, det map[string]string) {
		n, ok := nodes[id]
		if !ok {
			nodes[id] = &GraphNode{ID: id, Type: typ, Label: label, Confidence: conf, Tool: tool, CmdIndex: cmd, Offset: off, Details: det}
			order = append(order, id)
			return
		}
		// upgrade to high confidence / richer details if a better row appears
		if conf == "high" && n.Confidence != "high" {
			n.Confidence = "high"
			n.Tool = tool
			n.CmdIndex = cmd
			n.Offset = off
			if len(det) > 0 {
				n.Details = det
			}
			if label != "" {
				n.Label = label
			}
		}
	}
	addEdge := func(src, dst, typ, conf string, cmd int64) {
		if src == "" || dst == "" || src == dst {
			return
		}
		k := src + "|" + typ + "|" + dst
		if edgeSet[k] {
			return
		}
		edgeSet[k] = true
		edges = append(edges, GraphEdge{Source: src, Target: dst, Type: typ, Confidence: conf, CmdIndex: cmd})
	}

	parseDet := func(r EntityRow) map[string]string {
		det := map[string]string{}
		if r.Details != "" {
			_ = json.Unmarshal([]byte(r.Details), &det)
		}
		return det
	}

	// PASS 1 — create every node first (including hosts implied by a port or
	// hostname), so edge creation in pass 2 is independent of row order.
	for _, r := range rows {
		det := parseDet(r)
		switch r.Type {
		case "host":
			ensure("host:"+r.Value, "host", r.Value, r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
		case "port":
			ensure("port:"+r.Value, "port", portLabel(r.Value, det), r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
			if h := det["host"]; h != "" {
				ensure("host:"+h, "host", h, r.Confidence, r.Tool, r.CmdIndex, r.Offset, nil)
			}
		case "hostname":
			ensure("hostname:"+r.Value, "hostname", r.Value, r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
			if h := det["host"]; h != "" {
				ensure("host:"+h, "host", h, r.Confidence, r.Tool, r.CmdIndex, r.Offset, nil)
			}
		case "domain":
			if hostnameVals[r.Value] {
				continue // same name already a high-confidence hostname
			}
			ensure("domain:"+r.Value, "domain", r.Value, r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
		case "url", "endpoint":
			ensure(r.Type+":"+r.Value, r.Type, shortURL(r.Value), r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
		case "email":
			ensure("email:"+r.Value, "email", r.Value, r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
		case "finding":
			ensure(findingID(r.Value, det), "finding", findingLabel(r.Value, det), r.Confidence, r.Tool, r.CmdIndex, r.Offset, det)
		}
	}

	// Lookup aliases affect relationships only. Recorded node IDs, labels and
	// provenance remain unchanged, including different spellings in old data.
	hostNodes := graphHostLookup(nodes, order)
	// PASS 2 — edges, now that all endpoints exist.
	for _, r := range rows {
		det := parseDet(r)
		switch r.Type {
		case "port":
			if h := det["host"]; h != "" {
				linkToHostOrDomain(hostNodes, addEdge, "port:"+r.Value, h, "on", r.Confidence, r.CmdIndex)
			}
		case "hostname":
			if h := det["host"]; h != "" {
				linkToHostOrDomain(hostNodes, addEdge, "hostname:"+r.Value, h, "resolves", r.Confidence, r.CmdIndex)
			}
		case "url", "endpoint":
			if host := urlHost(r.Value); host != "" {
				linkToHostOrDomain(hostNodes, addEdge, r.Type+":"+r.Value, host, "on", r.Confidence, r.CmdIndex)
			}
		case "email":
			if at := strings.LastIndexByte(r.Value, '@'); at >= 0 && at+1 < len(r.Value) {
				linkToHostOrDomain(hostNodes, addEdge, "email:"+r.Value, r.Value[at+1:], "at", r.Confidence, r.CmdIndex)
			}
		case "finding":
			if h := det["host"]; h != "" {
				linkToHostOrDomain(hostNodes, addEdge, findingID(r.Value, det), h, "affects", r.Confidence, r.CmdIndex)
			}
		}
	}

	out := Graph{Nodes: make([]GraphNode, 0, len(order)), Edges: edges}
	for _, id := range order {
		out.Nodes = append(out.Nodes, *nodes[id])
	}
	if out.Edges == nil {
		out.Edges = []GraphEdge{}
	}
	return out, nil
}

// graphHostLookup is built once per graph, avoiding a scan of all nodes per
// relationship. Prefer an existing canonical ID as before; otherwise retain
// the first existing equivalent node in the graph's deterministic order.
func graphHostLookup(nodes map[string]*GraphNode, order []string) map[string]*GraphNode {
	lookup := make(map[string]*GraphNode)
	for _, id := range order {
		n := nodes[id]
		if n == nil {
			continue
		}
		switch n.Type {
		case "host", "hostname", "domain":
			value := strings.TrimPrefix(id, n.Type+":")
			key := n.Type + ":" + canonicalGraphHost(value)
			if lookup[key] == nil || id == key {
				lookup[key] = n
			}
		}
	}
	return lookup
}

func canonicalGraphHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		// String canonicalizes address bits while preserving the interface
		// zone's case. Do not Unmap IPv4-mapped IPv6 or merge scoped addresses.
		return addr.String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// linkToHostOrDomain uses graphHostLookup to link an existing node only.
// Aliases never invent nodes or replace the recorded target's original ID.
func linkToHostOrDomain(nodes map[string]*GraphNode, addEdge func(a, b, t, conf string, cmd int64), src, host, typ, conf string, cmd int64) {
	host = canonicalGraphHost(host)
	for _, pfx := range []string{"host:", "hostname:", "domain:"} {
		if node, ok := nodes[pfx+host]; ok {
			addEdge(src, node.ID, typ, conf, cmd)
			return
		}
	}
}

// findingID keys a finding by name AND its template/target/location, so two
// different findings that happen to share a name stay distinct (and the same
// finding is not merged across commands by name alone).
func findingID(value string, det map[string]string) string {
	return "finding:" + value + "\x1f" + det["template"] + "\x1f" + det["host"] + "\x1f" + det["matched"]
}

func findingLabel(value string, det map[string]string) string {
	if h := det["host"]; h != "" {
		return value + " @ " + h
	}
	return value
}

func portLabel(value string, det map[string]string) string {
	// value is "ip:port/proto"; prefer "port/proto service product"
	pp := value
	if i := strings.LastIndexByte(value, ':'); i >= 0 {
		pp = value[i+1:]
	}
	parts := []string{pp}
	if s := det["service"]; s != "" {
		parts = append(parts, s)
	}
	if p := det["product"]; p != "" {
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

func shortURL(u string) string {
	parsed, err := graphURL(u)
	if err != nil || parsed.Hostname() == "" {
		return "[invalid URL]"
	}
	// Labels must never expose credentials, including for bracketed IPv6.
	// Node IDs and edge provenance keep their existing entity representation.
	parsed.User = nil
	s := parsed.String()
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		s = strings.TrimPrefix(s, parsed.Scheme+"://")
	} else if parsed.Scheme == "" {
		s = strings.TrimPrefix(s, "//")
	}
	if chars := []rune(s); len(chars) > 40 {
		s = string(chars[:39]) + "…"
	}
	return s
}

func urlHost(u string) string {
	parsed, err := graphURL(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func graphURL(u string) (*url.URL, error) {
	if !strings.Contains(u, "://") && !strings.HasPrefix(u, "//") {
		u = "//" + u
	}
	return url.Parse(u)
}
