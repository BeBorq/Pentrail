// Package report is the final layer: it assembles a session's captured data,
// entities, cleanup checklist and graph into deliverables. A self-contained
// HTML report (offline, one file) for humans, and JSON/CSV exports for feeding
// the finding into other tooling (SysReptor / Dradis / Faraday) instead of
// competing with it. All read-only over data already captured.
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"github.com/BeBorq/Pentrail/internal/redact"
	"html/template"
	"sort"
	"strconv"
	"strings"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Bundle is everything a report needs for one session.
type Bundle struct {
	OutputMapping string
	Version       string
	Encrypted     bool
	Session       store.SessionInfo
	Commands      []store.CommandInfo
	Entities      []store.EntityRow
	Changes       []store.ChangeRow
	Graph         store.Graph
	CaptureEvents []store.CaptureEvent
	Artifacts     []store.ArtifactInfo
	// Operator notes are private by default: a report or export carries them
	// only when the user asked for them (--include-notes); then IncludeNotes
	// is true and Notes holds the session's active (not archived) notes.
	IncludeNotes bool
	Notes        []store.Note
}

// NotesNotice explains, wherever notes are exported, what they are.
const NotesNotice = "Operator notes: annotations written by the operator in the viewer. They are NOT captured evidence and were not recorded from the terminal. Recognized secrets were masked before they were stored. Archived notes are not included."

// ErrNotesCSV: the CSV export has one row per entity and no place for notes.
var ErrNotesCSV = errors.New("the CSV export contains entities only and cannot include operator notes; use --format json or the HTML report with --include-notes")

type notesExport struct {
	Notice string       `json:"notice"`
	Notes  []store.Note `json:"notes"`
}

// JSON is the machine-readable export (full fidelity, easy to transform into a
// vendor schema). Pretty-printed for diffs and review.
func JSON(b Bundle) ([]byte, error) {
	data, err := json.MarshalIndent(struct {
		OutputMapping   string               `json:"output_mapping,omitempty"`
		PentrailVersion string               `json:"pentrail_version"`
		Session         store.SessionInfo    `json:"session"`
		Commands        []store.CommandInfo  `json:"commands"`
		Entities        []store.EntityRow    `json:"entities"`
		Changes         []store.ChangeRow    `json:"changes"`
		Graph           store.Graph          `json:"graph"`
		CaptureEvents   []store.CaptureEvent `json:"capture_events"`
		Artifacts       []store.ArtifactInfo `json:"artifacts"`
		OperatorNotes   *notesExport         `json:"operator_notes,omitempty"`
	}{b.OutputMapping, b.Version, b.Session, b.Commands, b.Entities, b.Changes, b.Graph, b.CaptureEvents, b.Artifacts, operatorNotes(b)}, "", "  ")
	if err != nil {
		return nil, err
	}
	safe, e := redact.JSON(data)
	if e != nil {
		return nil, e
	}
	var pretty bytes.Buffer
	if e = json.Indent(&pretty, safe, "", "  "); e != nil {
		return nil, e
	}
	return pretty.Bytes(), nil
}

// operatorNotes is the separate notes field of the JSON export: present only
// when notes were asked for (an empty list then says "there are none").
func operatorNotes(b Bundle) *notesExport {
	if !b.IncludeNotes {
		return nil
	}
	n := b.Notes
	if n == nil {
		n = []store.Note{}
	}
	return &notesExport{Notice: NotesNotice, Notes: n}
}

// CSV exports the entities (one row per occurrence) — the simplest thing most
// tools and spreadsheets will ingest.
func CSV(b Bundle) ([]byte, error) {
	if b.IncludeNotes {
		return nil, ErrNotesCSV
	}
	var e error
	b, e = maskedBundle(b)
	if e != nil {
		return nil, e
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"type", "value", "confidence", "tool", "cmd_index", "offset", "details"})
	for _, e := range b.Entities {
		_ = w.Write([]string{csvCell(e.Type), csvCell(e.Value), e.Confidence, csvCell(e.Tool),
			strconv.FormatInt(e.CmdIndex, 10), strconv.FormatInt(e.Offset, 10), csvCell(e.Details)})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// ---- HTML report ----

type portView struct {
	Port, Proto, Service, Product, Version, Confidence string
}
type hostView struct {
	IP, State string
	Ports     []portView
}
type indicator struct {
	Type, Value, Confidence, Tool string
	CmdIndex                      int64
}

type htmlModel struct {
	B         Bundle
	Hosts     []hostView
	Domains   []indicator
	URLs      []indicator
	Emails    []indicator
	Findings  []indicator
	HighCount int
	LowCount  int
}

func buildModel(b Bundle) htmlModel {
	m := htmlModel{B: b}
	hostIdx := map[string]*hostView{}
	ensureHost := func(ip string) *hostView {
		if ip == "" {
			return nil
		}
		if h, ok := hostIdx[ip]; ok {
			return h
		}
		h := &hostView{IP: ip}
		hostIdx[ip] = h
		return h
	}
	for _, e := range b.Entities {
		if e.Confidence == "high" {
			m.HighCount++
		} else {
			m.LowCount++
		}
		det := map[string]string{}
		if e.Details != "" {
			_ = json.Unmarshal([]byte(e.Details), &det)
		}
		switch e.Type {
		case "host":
			h := ensureHost(e.Value)
			if det["state"] != "" {
				h.State = det["state"]
			}
		case "port":
			h := ensureHost(det["host"])
			if h == nil {
				continue
			}
			h.Ports = append(h.Ports, portView{
				Port: det["port"], Proto: det["proto"], Service: det["service"],
				Product: det["product"], Version: det["version"], Confidence: e.Confidence,
			})
		case "domain", "hostname":
			m.Domains = append(m.Domains, indicator{e.Type, e.Value, e.Confidence, e.Tool, e.CmdIndex})
		case "url", "endpoint":
			m.URLs = append(m.URLs, indicator{e.Type, e.Value, e.Confidence, e.Tool, e.CmdIndex})
		case "email":
			m.Emails = append(m.Emails, indicator{e.Type, e.Value, e.Confidence, e.Tool, e.CmdIndex})
		case "finding":
			m.Findings = append(m.Findings, indicator{e.Type, e.Value, e.Confidence, e.Tool, e.CmdIndex})
		}
	}
	for _, h := range hostIdx {
		sort.Slice(h.Ports, func(i, j int) bool {
			return atoi(h.Ports[i].Port) < atoi(h.Ports[j].Port)
		})
		m.Hosts = append(m.Hosts, *h)
	}
	sort.Slice(m.Hosts, func(i, j int) bool { return m.Hosts[i].IP < m.Hosts[j].IP })
	return m
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// HTML renders the standalone report.
func HTML(b Bundle) ([]byte, error) {
	var e error
	b, e = maskedBundle(b)
	if e != nil {
		return nil, e
	}
	m := buildModel(b)
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"msTime":      msTime,
	"artLabel":    ArtifactLabel,
	"endLabel":    EndLabel,
	"notesNotice": func() string { return NotesNotice },
}).Parse(reportHTML))

// EndLabel names why a command's end was not observed.
func EndLabel(reason string) string {
	switch reason {
	case store.EndSessionEnded:
		return "session ended while it ran"
	case store.EndRecordingPaused:
		return "recording paused while it ran"
	case store.EndCaptureRecovered:
		return "capture interrupted, range restored"
	}
	return reason
}

// ArtifactLabel is the human-readable name of an artifact state.
func ArtifactLabel(state string) string {
	switch state {
	case store.ArtWaiting:
		return "tool still running"
	case store.ArtPending:
		return "waiting for import"
	case store.ArtImported:
		return "imported (complete)"
	case store.ArtImportedPartial:
		return "imported PARTIALLY"
	case store.ArtRejected:
		return "rejected — invalid document"
	case store.ArtTooLarge:
		return "skipped — too large"
	case store.ArtMissing:
		return "file missing"
	case store.ArtUnreadable:
		return "unreadable"
	case store.ArtUnsafe:
		return "skipped — unsafe file type"
	case store.ArtLegacyUnchecked:
		return "plaintext copy from an older version"
	}
	return state
}

func maskedBundle(b Bundle) (Bundle, error) {
	v, e := json.Marshal(b)
	if e != nil {
		return b, e
	}
	v, e = redact.JSON(v)
	if e != nil {
		return b, e
	}
	var out Bundle
	e = json.Unmarshal(v, &out)
	return out, e
}

func csvCell(s string) string {
	if strings.ContainsAny(strings.TrimLeft(s, " \t\r\n")[:min(1, len(strings.TrimLeft(s, " \t\r\n")))], "=+-@") {
		return "'" + s
	}
	return s
}
