// Package extract is the low-confidence half of Layer 3: generic regex
// extraction of indicators (IPv4, domain, URL, e-mail) from the raw output of
// ANY tool. It runs offline over bytes already in the store, so it never
// touches the live terminal and can be re-run against an old capture after the
// rules improve.
//
// Everything here is confidence "low": a regex cannot tell a real host from a
// version string that looks like one. Structured per-tool parsers (nmap XML,
// nuclei JSONL, …) are the high-confidence half and come in a later step.
package extract

import (
	"regexp"
	"strings"
)

// Kind is an entity type produced by extraction.
type Kind string

const (
	KindHost   Kind = "host"   // IPv4 literal
	KindDomain Kind = "domain" // DNS name
	KindURL    Kind = "url"    // http(s) URL
	KindEmail  Kind = "email"  // e-mail address
)

// Match is one indicator found in a byte slice, with its offset relative to the
// start of that slice (so callers can map it back into the raw log).
type Match struct {
	Kind   Kind
	Value  string // normalized
	Offset int    // byte offset within the scanned slice
}

var (
	reIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b`)
	reURL  = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\]\[(){}]+`)
	reMail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reDom  = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b`)
)

// Run scans data and returns de-duplicated matches (per kind+value, first
// offset kept). Order: URLs and e-mails first, then hosts, then bare domains.
func Run(data []byte) []Match {
	data, positions := visibleTerminal(data)
	var out []Match
	seen := map[string]bool{} // kind|value

	add := func(k Kind, val string, off int) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		key := string(k) + "|" + val
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Match{Kind: k, Value: val, Offset: off})
	}

	for _, loc := range reURL.FindAllIndex(data, -1) {
		raw := string(data[loc[0]:loc[1]])
		add(KindURL, trimTrailing(raw), positions[loc[0]])
	}
	for _, loc := range reMail.FindAllIndex(data, -1) {
		add(KindEmail, strings.ToLower(string(data[loc[0]:loc[1]])), positions[loc[0]])
	}
	for _, loc := range reIPv4.FindAllIndex(data, -1) {
		add(KindHost, string(data[loc[0]:loc[1]]), positions[loc[0]])
	}
	for _, loc := range reDom.FindAllIndex(data, -1) {
		d := strings.ToLower(string(data[loc[0]:loc[1]]))
		if isLikelyNoise(d) {
			continue
		}
		add(KindDomain, d, positions[loc[0]])
	}
	return out
}

// trimTrailing removes punctuation commonly glued to the end of a URL in prose
// or tool output (e.g. "see http://x/y." or "(http://x/y)").
func trimTrailing(s string) string {
	return strings.TrimRight(s, ".,;:!?)]}>'\"")
}

// isLikelyNoise filters a few obvious non-domains the bare-domain regex catches.
// Deliberately conservative — this pass is low-confidence by design.
func isLikelyNoise(d string) bool {
	// filenames like "a.out", "index.html", "config.yaml" — common in tool
	// output and almost never a real domain.
	for _, ext := range noiseTLDs {
		if strings.HasSuffix(d, "."+ext) {
			return true
		}
	}
	return false
}

var noiseTLDs = []string{
	"exe", "dll", "ps1", "bat", "cmd", "pdb", "sys",
	"out", "html", "htm", "js", "css", "json", "yaml", "yml", "txt", "md",
	"go", "py", "sh", "c", "h", "cpp", "rs", "log", "conf", "cfg", "ini",
	"xml", "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "tar", "gz",
}

// Keep offsets in the stored stream while excluding OSC metadata and VT colors.
func visibleTerminal(raw []byte) ([]byte, []int) {
	var out []byte
	var positions []int
	for i := 0; i < len(raw); {
		if raw[i] == 27 && i+1 < len(raw) {
			if raw[i+1] == '[' {
				j := i + 2
				for j < len(raw) && (raw[j] < 0x40 || raw[j] > 0x7e) {
					j++
				}
				if j < len(raw) {
					i = j + 1
					continue
				}
				break
			}
			if raw[i+1] == ']' {
				j := i + 2
				for j < len(raw) && raw[j] != 7 && !(raw[j] == 27 && j+1 < len(raw) && raw[j+1] == '\\') {
					j++
				}
				if j == len(raw) {
					break
				}
				if raw[j] == 27 {
					i = j + 2
				} else {
					i = j + 1
				}
				continue
			}
			i += 2
			continue
		}
		out = append(out, raw[i])
		positions = append(positions, i)
		i++
	}
	return out, positions
}
