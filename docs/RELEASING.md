# Building and releasing

The script `release/build_release.py` builds the two release packages from
the current source tree:

- `windows-amd64`: `pentrail.exe`, SQLCipher, CGO through `zig cc`
  (target `x86_64-windows-gnu`);
- `linux-amd64`: a static `pentrail`, SQLCipher, CGO through `zig cc`
  (target `x86_64-linux-musl`).

Both can be built on either Windows or Linux. A successful build is **not a
test result**. The script does not sign, tag or publish anything.

## Requirements

- Python 3.8+ (standard library only).
- Go 1.27.3 and Zig 0.13.0, given as explicit paths (`--go`, `--zig`). The
  script refuses a Go whose `go version` differs from the `toolchain` line of
  `go.mod`, and runs its own `go version` calls with `GOTOOLCHAIN=local` so
  that a different Go never downloads and reports another toolchain. The
  script does not search `PATH` and does not download anything: it sets
  `GOTOOLCHAIN=local`, `GOPROXY=off` and `GOFLAGS=-mod=readonly`. Fill the
  module cache first, for example with `go mod download`.
- The license texts of the C runtime that `zig cc` links (musl for Linux,
  mingw-w64 for Windows) are copied verbatim from the Zig installation
  (`lib/libc/musl/COPYRIGHT`, `lib/libc/mingw/COPYING*`). If they are
  missing, the script refuses to package; you can then name the original
  file from the same upstream release with `--license-file musl=PATH` or
  `--license-file mingw-w64=PATH`. The script never writes license text
  itself.

## Commands

Plan and checks, without building or writing anything:

```sh
python3 release/build_release.py --go /path/to/go --zig /path/to/zig --out /new/directory --dry-run
```

Build:

```sh
python3 release/build_release.py --go /path/to/go --zig /path/to/zig --out /new/directory
python3 release/build_release.py ... --targets linux-amd64     # one platform only
```

On Windows: `py -3 release\build_release.py --go C:\path\to\go.exe --zig C:\path\to\zig.exe --out D:\staging\pentrail-<version>`.

`--out` must be a **new** directory outside the source tree; an existing
directory is refused and nothing is overwritten. The ZIP timestamps come from
`SOURCE_DATE_EPOCH` (default 315532800, 1980-01-01) and the file order is
fixed.

The exact build command (also printed by `--dry-run`):

```text
CGO_ENABLED=1 GOOS=<windows|linux> GOARCH=amd64 GOAMD64=v1
CC='"<zig>" cc -target <target>' CXX='"<zig>" c++ -target <target>'
CGO_CFLAGS=<see below> CGO_CPPFLAGS= CGO_CXXFLAGS='-O2 -g0' CGO_LDFLAGS='-O2' CGO_FFLAGS='-O2 -g0'
SOURCE_DATE_EPOCH=<ZIP timestamp>
GOENV=off GOEXPERIMENT= GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly
<go> build -tags sqlcipher -trimpath -buildvcs=false -ldflags '<flags>' -o <out>/build/<platform>/<binary> ./cmd/pentrail
```

All of these variables are set by the script; inherited values and a
`go env -w` profile do not change the build. Replaced inherited values are
printed and recorded in the manifest (`inherited_env_replaced`), and the
effective `go env -json` is recorded in `go_env`.

`CGO_CFLAGS`: Windows `-O2 -g0`; Linux `-O2 -g0 -D_LARGEFILE64_SOURCE` (musl
declares `off64_t`, `pread64` and `pwrite64`, used by the SQLCipher
amalgamation, only with this definition). Linker flags: Windows
`-s -w -buildid=`; Linux `-s -w -buildid= -linkmode external -extldflags -static`.

## Output

- `build/<platform>/<binary>` — the binaries;
- `pentrail-<version>-<platform>.zip` — the binary, `README.md`, `LICENSE`,
  `NOTICE`, `THIRD-PARTY-NOTICES.txt`, `SECURITY.md`, `CONTRIBUTING.md`, all
  documentation under `docs/` (so every relative link of the README works in
  the unpacked package) and `licenses/` (the musl or mingw-w64 license);
- `MANIFEST.json` — version, source tree hash (the rule is in the file), tool
  paths, versions and SHA-256, build environment and command, `go env`,
  compiler output, `go version -m`, check results and the SHA-256 of every
  package file. It is written atomically before the build and after each
  platform; `result` is `in_progress`, `succeeded` or `failed`;
- `BUILDINFO-public.json` — written only after a successful build: the
  manifest without local paths (they are replaced by `<source tree>`,
  `<output directory>`, `<go tool>`, `<zig tool>`, `<home>` and the Go cache
  names), without `go env` and without compiler output. The script refuses to
  write it, and marks the build failed, if anything that looks like an
  absolute path remains;
- `SHA256SUMS` — the binaries and packages actually produced;
- `zig-cache/` — Zig's cache for this build.

`MANIFEST.json` is the private build record: it contains absolute local
paths, the environment and compiler output. Publish `BUILDINFO-public.json`
and `SHA256SUMS` next to the packages, not `MANIFEST.json`.

A failure on one platform does not stop the other. The manifest then has
`result: failed`, `SHA256SUMS` lists what was produced, and the script exits
with code 1 and `BUILD FAILED (...)`. A package from a failed build is not a
release package.

## Checks done by the script

No package is produced when one of these fails (see `problems` in the
manifest):

- `go version -m`: `CGO_ENABLED=1`, `-tags=sqlcipher`, the right GOOS/GOARCH,
  `go-sqlcipher` linked;
- the binary contains the version string from `cmd/pentrail/main.go`;
- the binary contains none of the local paths of the build (source tree,
  output directory, Go and Zig directories, Go caches, home directory);
- every linked Go module has a license section in `THIRD-PARTY-NOTICES.txt`,
  plus the Go runtime section;
- Linux: the ELF file has no `PT_INTERP` header (static);
- every ZIP entry is "made by" Unix with the intended mode (binary 0755,
  documents 0644) and its bytes match the source;
- Windows: the PE import table contains only system libraries and the UCRT
  API set (`api-ms-win-*`).

## Reproducibility

`-g0` removes C debug data that contains the source path, `-buildid=`
removes the Go build ID, and a fixed `SOURCE_DATE_EPOCH` also fixes
`COFF.TimeDateStamp` in the Windows executable (Zig 0.13 uses it). The
script does not rewrite any bytes of the built files.

To show that a build is reproducible, build the same sources twice in
different directories with the same Go, Zig and `SOURCE_DATE_EPOCH`, and
compare all bytes of both binaries and ZIPs. A valid manifest or an equal
source hash alone is not such proof.

## Verification by the recipient

1. Compare `sha256sum` / `Get-FileHash` of the packages with `SHA256SUMS`.
2. Unpack into a temporary directory and read `LICENSE`, `NOTICE`,
   `THIRD-PARTY-NOTICES.txt` and `licenses/`.
3. Linux: `readelf -l pentrail | grep -i interp` prints nothing;
   `go version -m pentrail` shows `-tags=sqlcipher` and `CGO_ENABLED=1`.
   Unpacked with Info-ZIP `unzip` as a regular user (`umask 022`), the binary
   is `-rwxr-xr-x` and runs. (Not every tool applies Unix modes; Python's
   `zipfile` does not.)
4. Windows: `go version -m pentrail.exe`; `dumpbin /imports` (if available)
   shows only system and UCRT libraries.
5. Rebuild from the tagged sources and compare the SHA-256 of the binaries.

## Release procedure

Releases are made by hand; CI does not publish anything.

1. Set the version in `cmd/pentrail/main.go` and update
   [RELEASE-NOTES.md](RELEASE-NOTES.md).
2. Run the full tests on Linux and native Windows ([TESTING.md](TESTING.md)).
3. Build both packages twice with `build_release.py` in new directories and
   compare the bytes.
4. Verify the packages as above and run the release binaries on a clean test
   profile with synthetic data.
5. Run `govulncheck` on the release binaries and record the result (see
   [SECURITY-MODEL.md](SECURITY-MODEL.md#dependency-audit)).
6. Tag the commit (`v<version>`) and create a GitHub release with the two ZIP
   files, `SHA256SUMS` and `BUILDINFO-public.json`. Mark it as a pre-release while it is a candidate.
   State in the release text that the packages are unsigned.
