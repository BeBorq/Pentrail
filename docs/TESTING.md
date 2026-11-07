# Testing

All tests run offline and use synthetic data in temporary directories. They
do not change your shell profiles, registry values or Pentrail database.

## Requirements

- Go 1.27.3 and a C compiler for CGO (`gcc`/`clang` on Linux, MinGW-w64
  `gcc` on Windows). `go.mod` requires at least Go 1.25.0 and names
  `toolchain go1.27.3`: with an older local Go, `GOTOOLCHAIN=auto` (the
  default) downloads Go 1.27.3, and `GOTOOLCHAIN=local` uses the local Go.
- Python 3.8+ for the release script tests.
- Node.js 20 or newer for the viewer tests. They are started by
  `go test ./internal/view` and skipped when `node` is not on `PATH`.
- Linux: Bash; tests that need Zsh are skipped when it is not installed.
- Windows: Windows PowerShell 5.1 and CMD; tests that need PowerShell 7 are
  skipped when `pwsh` is not installed. Tests that create symbolic links are
  skipped without the privilege to create them.

## Standard suites

```sh
CGO_ENABLED=1 go test -count=1 ./...                    # unencrypted development build
CGO_ENABLED=1 go test -tags sqlcipher -count=1 ./...    # encrypted (release) build
go vet ./... && go vet -tags sqlcipher ./...
GOOS=windows CGO_ENABLED=0 go vet ./...                 # Windows code paths, from Linux
python3 release/test_build_release.py                   # release script: public build info, local paths, package links
```

PowerShell:

```powershell
$env:CGO_ENABLED = '1'
go test -count=1 ./...
go test -tags sqlcipher -count=1 ./...
```

The `.github/workflows/tests.yml` workflow runs both suites on Ubuntu and
Windows, plus `gofmt`, `go mod verify`, the Windows compile check and the
release script tests. It has
read-only permissions and does not build or publish release packages.

## What the suites cover

| Package | Main subjects |
|---|---|
| `internal/redact` | masking rules, every byte split of the examples, ConPTY line breaks, JSON/XML artifacts |
| `internal/store` | schema and migrations, crash recovery of the checkpoint buffer, WAL backup, notes revisions |
| `internal/capture` | PTY/ConPTY capture, markers, CMD and PowerShell segmentation, replay of recorded native Windows traces (`testdata/`), crash and kill tests |
| `internal/sessionio` | frames, handshake, flow control, pacing takeover, slow clients |
| `internal/view` | HTTP guard (token, Host, Origin), read-only API, notes API, and the JavaScript tests below |
| `cmd/pentrail` | CLI behaviour, setup idempotence, protection flags |

### Viewer JavaScript tests

`internal/view/*.test.cjs` and `*.regression.test.cjs` run the real page code
(`index.html` and the modules) in Node with a fake DOM and a controllable
clock. They cover the graph layout and interaction, cross-references,
cleanup state, notes drafts and conflicts, and failure handling of every read
(connection errors, HTTP 401/403/404/500, invalid data, a request or a reply
body that never finishes, stale replies and retired retry buttons). `go test`
starts them with the arguments they need. Some can also be run directly:

```sh
node internal/view/reads.regression.test.cjs
node internal/view/loading.regression.test.cjs
node internal/view/graph.regression.test.cjs internal/view
```

`rendergraph.regression.test.cjs` and `rendercleanup.regression.test.cjs` take
a part of `index.html` that the Go tests extract; run them through
`go test ./internal/view`.

These are not browser tests. Rendering in real browsers is checked by hand.

## Opt-in end-to-end tests

Some tests drive a real built binary or several real terminals and are
skipped unless enabled:

| Variable | Enables |
|---|---|
| `PENTRAIL_TEST_BINARY=/path/to/pentrail` | tests against a built package binary (workflow, upgrade, protection) |
| `PENTRAIL_MULTI_TERMINALS=1` | several real terminals of one database |
| `PENTRAIL_TRANSPORT_ACCEPTANCE=1` | Linux transport acceptance (stopped client, takeover, resize, Ctrl+C) |
| `PENTRAIL_FLOW_MIB`, `PENTRAIL_BIG_MIB` | larger output volumes for the flow tests |

`cmd/background-evidence` is an end-to-end program for Linux. It creates a
temporary home directory and runs `setup`, `on`, `off`, the viewer and real
Bash and Zsh terminals there. It expects the binary under test at
`/tests/pentrail` and starts background processes, so run it only in an
isolated test machine.

## Reporting results

When you report a test result, say where it ran: native Windows, native
Linux, a virtual machine, or a headless browser. These are not
interchangeable — for example ConPTY behaviour can only be checked on
Windows, and a headless Chromium run does not show how a desktop browser
renders the viewer.
