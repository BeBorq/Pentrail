# Contributing to Pentrail

Thank you for helping. Pentrail records evidence, so changes are judged first
by whether the record stays truthful: nothing may be reported as captured,
complete or saved unless it was.

## Ground rules

- **Synthetic data only.** Tests, fixtures, screenshots, issues and pull
  requests must not contain real hosts, user names, paths, credentials or
  terminal output from real work. Use reserved names such as `example.com`,
  `198.51.100.0/24`, `/home/analyst/lab` and clearly fake secrets.
- **No silent loss.** Capture and store changes must keep the order "commit,
  then show", keep offsets valid and report gaps instead of hiding them.
- **Masking only widens.** A change to `internal/redact` must not stop masking
  something that is masked today; add tests for every new rule, including
  split chunks.
- **The viewer never changes evidence.** Operator notes are the only writes.
- **No network access** in the program or in tests, and no new dependencies
  without a strong reason (each one needs its license added to
  `THIRD-PARTY-NOTICES.txt` and `release/build_release.py`).
- English for code, comments, user-facing text and documentation.

## Development setup

- Go 1.27.3 (`toolchain` in `go.mod`; at least Go 1.25.0), a C compiler for CGO (`gcc` or `clang` on Linux,
  MinGW-w64 `gcc` on Windows).
- Node.js 20 or newer, for the viewer's JavaScript tests (run by `go test`;
  they are skipped when `node` is not on `PATH`).
- Linux tests use Bash; some also use Zsh when it is installed.

## Before opening a pull request

```sh
gofmt -l .                                      # must print nothing
go vet ./...
go vet -tags sqlcipher ./...
CGO_ENABLED=1 go test -count=1 ./...
CGO_ENABLED=1 go test -tags sqlcipher -count=1 ./...
python3 release/test_build_release.py
```

On Windows run the same commands in PowerShell with `$env:CGO_ENABLED='1'`.
If you change platform-specific code, also check that the other platform
still compiles:

```sh
GOOS=windows CGO_ENABLED=0 go vet ./...         # from Linux
```

More on the tests, including the end-to-end checks that are not run by
default: [docs/TESTING.md](docs/TESTING.md).

## Pull requests

- Keep a change focused; explain what it changes and how you tested it.
- Add a regression test that fails without your change.
- Update the documentation in `docs/` when behaviour or a limit changes.
- Never commit databases (`*.db`, `*-wal`, `*-shm`), backups, reports,
  exports, logs, build output or screenshots that show real data.

By contributing you agree that your contribution is licensed under the MIT
License of this project.
