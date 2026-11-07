package report

import "time"

func msTime(ms int64) string {
	if ms == 0 {
		return "—"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}

const reportHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>pentrail — session report {{.B.Session.ID}}</title>
<style>
  :root{--fg:#1b1f24;--dim:#636c76;--line:#d0d7de;--bg:#fff;--panel:#f6f8fa;--ok:#1a7f37;--bad:#cf222e;--accent:#0969da;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  @media print{body{font-size:11px}.noprint{display:none}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
  .page{max-width:1000px;margin:0 auto;padding:28px 32px 60px}
  h1{font-size:22px;margin:0 0 4px}
  h2{font-size:15px;margin:28px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
  .sub{color:var(--dim);font:12px var(--mono)}
  .cards{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}
  .card{border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px;background:var(--panel)}
  .card .n{font-size:22px;font-weight:700}
  .card .l{color:var(--dim);font-size:12px}
  table{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}
  th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.3px}
  td.mono,.mono{font-family:var(--mono);font-size:12px;word-break:break-all}
  .host{margin-top:12px;border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .host .hh{background:var(--panel);padding:8px 12px;font-family:var(--mono);font-weight:600}
  .host table{margin:0}
  .badge{font:11px var(--mono);padding:1px 6px;border-radius:9px;border:1px solid var(--line)}
  .hi{color:var(--ok);border-color:#1a7f3755}
  .lo{color:var(--dim)}
  .ok{color:var(--ok)}.bad{color:var(--bad)}
  .cat{font:11px var(--mono);padding:1px 6px;border-radius:9px;border:1px solid var(--line)}
  .empty{color:var(--dim);font-style:italic;padding:6px 0}
  h2.notes{color:#9a6700;border-bottom-style:dashed}
  .notice{color:var(--dim);font-size:12px}
  tr.note td{background:#fff8c5}
  .ntitle{font-weight:600;white-space:pre-wrap;overflow-wrap:anywhere}
  .nbody{white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--mono);font-size:12px;margin-top:4px}
  footer{margin-top:40px;color:var(--dim);font-size:11px;border-top:1px solid var(--line);padding-top:10px}
</style></head>
<body><div class="page">
  {{if .B.OutputMapping}}<p class="sub">Windows ConPTY: the full session record is the source of the output. The output ranges of single commands are auxiliary and do not prove completeness.</p>{{end}}
  <h1>pentrail — session report {{.B.Session.ID}}</h1>
  <div class="sub">
    shell {{.B.Session.Shell}} · host {{.B.Session.Host}} ·
    {{msTime .B.Session.StartedMs}} → {{msTime .B.Session.EndedMs}} ·
    pentrail {{.B.Version}}
  </div>

  <div class="cards">
    <div class="card"><div class="n">{{.B.Session.Commands}}</div><div class="l">commands</div></div>
    <div class="card"><div class="n">{{.HighCount}}</div><div class="l">entities (high confidence)</div></div>
    <div class="card"><div class="n">{{.LowCount}}</div><div class="l">entities (regex)</div></div>
    <div class="card"><div class="n">{{len .B.Changes}}</div><div class="l">changes to clean up</div></div>
    <div class="card"><div class="n">{{.B.Session.RawBytes}}</div><div class="l">bytes of raw log</div></div>
  </div>

  <h2>Hosts and ports</h2>
  {{if .Hosts}}{{range .Hosts}}
    <div class="host">
      <div class="hh">{{.IP}}{{if .State}} · {{.State}}{{end}}</div>
      {{if .Ports}}<table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Confidence</th></tr></thead><tbody>
      {{range .Ports}}<tr><td class="mono">{{.Port}}/{{.Proto}}</td><td>{{.Service}}</td><td>{{.Product}}</td><td class="mono">{{.Version}}</td><td><span class="badge {{if eq .Confidence "high"}}hi{{else}}lo{{end}}">{{.Confidence}}</span></td></tr>{{end}}
      </tbody></table>{{else}}<div class="empty" style="padding:8px 12px">no open ports</div>{{end}}
    </div>
  {{end}}{{else}}<div class="empty">no hosts</div>{{end}}

  {{if .Findings}}<h2>Findings</h2>
  <table><thead><tr><th>Finding</th><th>Tool</th><th>Command</th></tr></thead><tbody>
  {{range .Findings}}<tr><td>{{.Value}}</td><td class="mono">{{.Tool}}</td><td class="mono">#{{.CmdIndex}}</td></tr>{{end}}
  </tbody></table>{{end}}

  <h2>Other indicators</h2>
  <table><thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Tool</th><th>Cmd</th></tr></thead><tbody>
  {{range .Domains}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td><span class="badge {{if eq .Confidence "high"}}hi{{else}}lo{{end}}">{{.Confidence}}</span></td><td class="mono">{{.Tool}}</td><td class="mono">#{{.CmdIndex}}</td></tr>{{end}}
  {{range .URLs}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td><span class="badge {{if eq .Confidence "high"}}hi{{else}}lo{{end}}">{{.Confidence}}</span></td><td class="mono">{{.Tool}}</td><td class="mono">#{{.CmdIndex}}</td></tr>{{end}}
  {{range .Emails}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td><span class="badge {{if eq .Confidence "high"}}hi{{else}}lo{{end}}">{{.Confidence}}</span></td><td class="mono">{{.Tool}}</td><td class="mono">#{{.CmdIndex}}</td></tr>{{end}}
  {{if and (not .Domains) (not .URLs) (not .Emails)}}<tr><td colspan="5" class="empty">none</td></tr>{{end}}
  </tbody></table>

  <h2>Cleanup checklist</h2>
  {{if .B.Changes}}<table><thead><tr><th>Category</th><th>Description</th><th>Command</th><th>Cmd</th><th>Time</th></tr></thead><tbody>
  {{range .B.Changes}}<tr><td><span class="cat">{{.Category}}</span></td><td>{{.Description}}</td><td class="mono">{{.Command}}</td><td class="mono">#{{.CmdIndex}}</td><td class="mono">{{msTime .DetectedMs}}</td></tr>{{end}}
  </tbody></table>{{else}}<div class="empty">no target state changes detected</div>{{end}}

  {{if .B.CaptureEvents}}<h2>Recording turned on and off</h2>
  <p>Periods with recording off are not part of the raw record.</p>
  <ul>{{range .B.CaptureEvents}}<li>{{msTime .AtMs}} — {{if .Recording}}on{{else}}off{{end}}</li>{{end}}</ul>{{end}}

  {{if .B.Artifacts}}<h2>Tool output files</h2>
  <p>Import state of every nmap/ffuf/nuclei file. Items marked red need attention:
  the file is not completely in the database or its plaintext copy is still on disk.</p>
  <table><thead><tr><th>Cmd</th><th>Tool</th><th>State</th><th>Details</th></tr></thead><tbody>
  {{range .B.Artifacts}}<tr>
    <td class="mono">#{{.CmdIndex}}</td>
    <td class="mono">{{.Tool}}</td>
    <td>{{if or .Partial .CleanupPending .CleanupDetail (and (ne .State "imported") (ne .State "waiting") (ne .State "pending"))}}<span class="bad">{{artLabel .State}}</span>{{else}}{{artLabel .State}}{{end}}</td>
    <td>{{.Detail}}{{if .CleanupPending}} Plaintext copy waiting for deletion.{{end}}{{if .CleanupDetail}} {{.CleanupDetail}}{{end}}<div class="mono" style="color:var(--dim)">{{.Path}}</div></td>
  </tr>{{end}}
  </tbody></table>{{end}}

  <h2>Command timeline</h2>
  <table><thead><tr><th>Cmd</th><th>Time</th><th>Result</th><th>Command</th><th>Directory</th></tr></thead><tbody>
  {{range .B.Commands}}<tr>
    <td class="mono">#{{.Index}}</td>
    <td class="mono">{{msTime .StartedMs}}</td>
    <td class="mono">{{if .EndReason}}<span title="the end of the command was not observed ({{.EndReason}}); exit code unknown">? ({{endLabel .EndReason}})</span>{{else if .Complete}}{{if eq .ExitCode 0}}<span class="ok">0</span>{{else}}<span class="bad">{{.ExitCode}}</span>{{end}}{{else}}…{{end}}</td>
    <td class="mono">{{.Command}}</td>
    <td class="mono">{{.Cwd}}</td>
  </tr>{{end}}
  </tbody></table>

  {{if .B.IncludeNotes}}<h2 class="notes">Operator notes — annotations, not captured evidence</h2>
  <p class="notice">{{notesNotice}}</p>
  {{if .B.Notes}}<table><thead><tr><th>Attached to</th><th>Note</th><th>Created</th><th>Last change</th></tr></thead><tbody>
  {{range .B.Notes}}<tr class="note">
    <td class="mono">{{if .AnchorLabel}}{{.AnchorLabel}}{{else}}session{{end}}</td>
    <td><div class="ntitle">{{if .Title}}{{.Title}}{{else}}(untitled){{end}}</div><div class="nbody">{{.Body}}</div></td>
    <td class="mono">{{msTime .CreatedMs}}</td>
    <td class="mono">{{msTime .UpdatedMs}} · rev {{.Revision}}</td>
  </tr>{{end}}
  </tbody></table>{{else}}<div class="empty">no operator notes for this session</div>{{end}}{{end}}

  <footer>
    Generated by pentrail {{.B.Version}}. The raw log is the source of truth
    {{if .B.Encrypted}}(database encrypted with SQLCipher){{else}}(WARNING: build without encryption — database in plaintext){{end}};
    the entities and this analysis are derived from it. All data stayed local.
  </footer>
</div></body></html>`
