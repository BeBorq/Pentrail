#!/usr/bin/env python3
"""Reproducible build of the Pentrail release packages.

Builds, from the CURRENT source tree, with the Go and Zig executables the
user names explicitly:

  * windows-amd64: pentrail.exe (SQLCipher, CGO via `zig cc`, x86_64-windows-gnu)
  * linux-amd64:   pentrail     (SQLCipher, static, CGO via `zig cc`, x86_64-linux-musl)

and packs each with the documentation and the third-party notices into a NEW
staging directory, with a manifest (tool versions, tool SHA-256, exact
commands and environment, source-tree hash, output SHA-256) and SHA256SUMS.

It never installs or downloads anything (GOTOOLCHAIN=local, GOPROXY=off,
-mod=readonly: missing modules make the build FAIL instead of fetching), never
touches dist/ or user profiles, refuses an existing output directory or one
inside the source tree, and does not sign or publish. A successful build is
not a test result. Python 3.8+, standard library only.

Usage (see docs/RELEASING.md):

  python3 release/build_release.py --go /path/to/go --zig /path/to/zig --out /new/staging/dir
  python3 release/build_release.py --go ... --zig ... --out ... --dry-run   # plan + checks, no build
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Documentation shipped in every package (all must exist in the source tree).
DOCS_COMMON = [
    "README.md", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt", "SECURITY.md", "CONTRIBUTING.md",
    "docs/QUICKSTART.md", "docs/USER-GUIDE.md", "docs/COMMANDS.md", "docs/DATA-PROTECTION.md",
    "docs/SECURITY-MODEL.md", "docs/LIMITATIONS.md", "docs/BACKUP-RECOVERY.md", "docs/HOW-IT-WORKS.md",
    "docs/SESSION-TRANSPORT.md", "docs/FAQ.md", "docs/RELEASE-NOTES.md", "docs/TESTING.md", "docs/RELEASING.md",
    "docs/WINDOWS.md", "docs/LINUX.md",
    "docs/images/timeline.png", "docs/images/graph.png", "docs/images/notes.png",
]
# Every package carries the same documents, so that every relative link of
# README.md and docs/ resolves inside the unpacked package as in the
# repository (release/test_build_release.py checks this).
DOCS_PLATFORM = {"windows-amd64": [], "linux-amd64": []}

# Go module -> the section of THIRD-PARTY-NOTICES.txt that carries its license.
# A module linked into a binary but absent here makes the package step FAIL:
# license texts are never invented by this script.
NOTICE_SECTIONS = {
    "github.com/creack/pty": "=== creack/pty ===",
    "github.com/mattn/go-sqlite3": "=== go-sqlite3 ===",
    "github.com/mutecomm/go-sqlcipher/v4": "=== go-sqlcipher ===",
    "github.com/Microsoft/go-winio": "=== Microsoft/go-winio ===",
    "golang.org/x/sys": "=== golang.org/x/sys ===",
}
GO_RUNTIME_SECTION = "=== Go runtime ==="

# C runtime code that `zig cc` links into the binaries. Its license text is
# copied verbatim from the Zig installation the user names (it ships the
# sources it links); if the file is not there, packaging FAILS.
LIBC_LICENSES = {
    "linux-amd64": [("musl", ["lib/libc/musl/COPYRIGHT"])],
    "windows-amd64": [("mingw-w64", ["lib/libc/mingw/COPYING", "lib/libc/mingw/COPYING.MinGW-w64-runtime.txt",
                                     "lib/libc/mingw/COPYING.MinGW-w64-runtime"])],
}

TARGETS = {
    "windows-amd64": {"goos": "windows", "zig_target": "x86_64-windows-gnu", "binary": "pentrail.exe", "ldflags": "-s -w -buildid=",
                      "cgo_cflags": "-O2 -g0"},
    # musl declares off64_t/pread64/pwrite64 (used by the SQLCipher amalgamation)
    # only with _LARGEFILE64_SOURCE (without it the Linux build fails to compile)
    "linux-amd64": {"goos": "linux", "zig_target": "x86_64-linux-musl", "binary": "pentrail",
                    "ldflags": "-s -w -buildid= -linkmode external -extldflags -static", "cgo_cflags": "-O2 -g0 -D_LARGEFILE64_SOURCE"},
}

# Windows DLLs a release binary may import (system DLLs and the UCRT API set).
WINDOWS_SYSTEM_DLLS = {
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "ws2_32.dll", "user32.dll", "shell32.dll", "ole32.dll",
    "bcrypt.dll", "crypt32.dll", "secur32.dll", "userenv.dll", "winmm.dll", "iphlpapi.dll", "ucrtbase.dll",
    "msvcrt.dll", "powrprof.dll", "dbghelp.dll", "mswsock.dll",
}


class Fail(Exception):
    """A refusal or failure; main() reports it and exits non-zero. Inside the
    build loop it is recorded for the target in MANIFEST.json first."""


class CommandFailed(Fail):
    def __init__(self, cmd, code, output):
        Fail.__init__(self, "command failed (%d): %s" % (code, " ".join(shlex.quote(c) for c in cmd)))
        self.cmd, self.code, self.output = cmd, code, output


def die(msg):
    raise Fail(msg)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def required_toolchain():
    """The `toolchain goX.Y.Z` line of go.mod, or None."""
    with open(os.path.join(ROOT, "go.mod"), encoding="utf-8") as f:
        m = re.search(r"^toolchain\s+(go\S+)\s*$", f.read(), re.M)
    return m.group(1) if m else None


def check_toolchain(go_version_output):
    """A release is built with exactly the Go named in go.mod (older Go
    standard libraries have known vulnerabilities)."""
    want = required_toolchain()
    got = (go_version_output.split() + ["", "", ""])[2]
    if want and got != want:
        raise Fail("go.mod names toolchain %s, but --go is %s; give the matching Go" % (want, got or "unknown"))


def tool_env():
    """Environment for the script's own `go version`/`go version -m` calls:
    the named Go must answer itself. Without GOTOOLCHAIN=local an older Go
    would download the toolchain named in go.mod and report that instead."""
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOENV": "off"})
    return env


def run(cmd, env=None, cwd=ROOT):
    p = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    if p.returncode != 0:
        raise CommandFailed(cmd, p.returncode, out)
    return out


def source_tree():
    """Every file of the source tree except dist/, .git/ and caches: (relpath, sha256)."""
    files = []
    for base, dirs, names in os.walk(ROOT):
        rel_base = os.path.relpath(base, ROOT)
        dirs[:] = sorted(d for d in dirs if not (rel_base == "." and d in ("dist", ".git")) and d != "__pycache__")
        for n in sorted(names):
            p = os.path.join(base, n)
            if os.path.isfile(p) and not os.path.islink(p):
                files.append((os.path.relpath(p, ROOT).replace(os.sep, "/"), sha256_file(p)))
    files.sort()
    h = hashlib.sha256()
    for rel, digest in files:
        h.update(("%s\0%s\n" % (rel, digest)).encode())
    return files, h.hexdigest()


def project_version():
    src = open(os.path.join(ROOT, "cmd", "pentrail", "main.go"), encoding="utf-8").read()
    m = re.search(r'const version = "([^"]+)"', src)
    if not m:
        die("version constant not found in cmd/pentrail/main.go")
    return m.group(1)


def notice_sections():
    text = open(os.path.join(ROOT, "THIRD-PARTY-NOTICES.txt"), encoding="utf-8").read()
    return {line.strip() for line in text.splitlines() if line.startswith("=== ")}


def check_out_dir(out):
    out = os.path.abspath(out)
    if os.path.exists(out):
        die("output directory exists: %s (refusing to overwrite; give a NEW directory)" % out)
    root = os.path.realpath(ROOT)
    parent = os.path.realpath(os.path.dirname(out))
    full = os.path.join(parent, os.path.basename(out))
    if full == root or full.startswith(root + os.sep):
        die("output directory must be outside the source tree (%s)" % root)
    if not os.path.isdir(parent):
        die("parent of the output directory does not exist: %s" % parent)
    return full


def tool(path, name):
    p = os.path.abspath(path)
    if not os.path.isfile(p) or not os.access(p, os.X_OK):
        die("%s executable not found or not executable: %s" % (name, p))
    return p


def build_env(go, zig, target, zig_cache):
    """The build environment: every variable that changes how Go or cgo
    builds is SET here (an inherited CGO_CFLAGS, GOFLAGS or a `go env -w`
    profile must not change a release build; GOENV=off ignores that profile).
    Returns (environment, the variables set, inherited values they replaced)."""
    t = TARGETS[target]
    env = dict(os.environ)
    cc = '"%s" cc -target %s' % (zig, t["zig_target"])
    cxx = '"%s" c++ -target %s' % (zig, t["zig_target"])
    fixed = {
        "CGO_ENABLED": "1", "GOOS": t["goos"], "GOARCH": "amd64", "GOAMD64": "v1",
        "CC": cc, "CXX": cxx,
        "CGO_CFLAGS": t["cgo_cflags"], "CGO_CPPFLAGS": "", "CGO_CXXFLAGS": "-O2 -g0",
        "CGO_LDFLAGS": "-O2", "CGO_FFLAGS": "-O2 -g0",
        "SOURCE_DATE_EPOCH": str(int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))),
        "GOENV": "off", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "-mod=readonly",
        "ZIG_GLOBAL_CACHE_DIR": zig_cache, "ZIG_LOCAL_CACHE_DIR": zig_cache,
    }
    replaced = {k: os.environ[k] for k in fixed if k in os.environ and os.environ[k] != fixed[k]}
    env.update(fixed)
    return env, fixed, replaced


def build_cmd(go, target, out_bin):
    t = TARGETS[target]
    return [go, "build", "-tags", "sqlcipher", "-trimpath", "-buildvcs=false",
            "-ldflags", t["ldflags"], "-o", out_bin, "./cmd/pentrail"]


# --- binary checks (no execution of the built binaries) ---

def elf_interp(path):
    """True if the ELF file has a PT_INTERP header (dynamically linked)."""
    with open(path, "rb") as f:
        hdr = f.read(64)
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
            die("%s is not a 64-bit ELF file" % path)
        phoff, = struct.unpack_from("<Q", hdr, 32)
        phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            p_type, = struct.unpack("<I", f.read(4))
            if p_type == 3:  # PT_INTERP
                return True
    return False


def pe_imports(path):
    """DLL names in the PE import table (lower case)."""
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        die("%s is not a PE file" % path)
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        die("%s: bad PE signature" % path)
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    if magic != 0x20B:
        die("%s: not PE32+ (amd64)" % path)
    imp_rva, imp_size = struct.unpack_from("<II", data, opt + 112 + 8)  # data directory 1: imports
    secs = []
    for i in range(nsec):
        s = pe + 24 + optsize + i * 40
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        secs.append((va, max(vsize, rsize), raw))

    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return raw + rva - va
        die("%s: RVA %#x outside sections" % (path, rva))

    names = []
    if imp_rva:
        o = off(imp_rva)
        while True:
            name_rva, = struct.unpack_from("<I", data, o + 12)
            if name_rva == 0:
                break
            n = off(name_rva)
            names.append(data[n:data.index(b"\0", n)].decode("ascii", "replace").lower())
            o += 20
    return names


def go_buildinfo(go, binary):
    out = run([go, "version", "-m", binary], env=tool_env())
    deps, settings = {}, {}
    for line in out.splitlines():
        f = line.strip().split("\t")
        if f[0] == "dep" and len(f) >= 3:
            deps[f[1]] = f[2]
        elif f[0] == "build" and len(f) >= 2 and "=" in f[1]:
            k, v = f[1].split("=", 1)
            settings[k] = v
    return out, deps, settings


def private_path_hits(binary, private_paths):
    """Labels of the local paths (source tree, output, tools, Go caches, home)
    whose text appears in the binary; a public binary must contain none."""
    with open(binary, "rb") as f:
        data = f.read().lower()
    hits = []
    for label, p in sorted(private_paths.items()):
        if not p or len(p) < 4:
            continue
        # a path embedded in a binary continues with a separator; "/root"
        # alone must not match Go's own "os/root_unix.go"
        forms = {p, p.replace("\\", "/"), p.replace("/", "\\")}
        if any((f.lower() + sep).encode("utf-8", "replace") in data for f in forms for sep in ("/", "\\")):
            hits.append(label)
    return hits


def verify_binary(go, target, binary, version, sections, private_paths=None):
    report = {}
    raw, deps, settings = go_buildinfo(go, binary)
    report["go_version_m"] = raw
    problems = []
    hits = private_path_hits(binary, private_paths or {})
    report["local_paths_in_binary"] = hits
    if hits:
        problems.append("the binary contains local paths (%s); build with -trimpath from neutral directories" % ", ".join(hits))
    if settings.get("CGO_ENABLED") != "1":
        problems.append("CGO_ENABLED is not 1")
    if "sqlcipher" not in settings.get("-tags", "").split(","):
        problems.append("built without -tags sqlcipher")
    if settings.get("GOOS") != TARGETS[target]["goos"] or settings.get("GOARCH") != "amd64":
        problems.append("wrong GOOS/GOARCH: %s/%s" % (settings.get("GOOS"), settings.get("GOARCH")))
    if "github.com/mutecomm/go-sqlcipher/v4" not in deps:
        problems.append("go-sqlcipher not linked")
    if version.encode() not in open(binary, "rb").read():
        problems.append("version string %r not found in the binary" % version)
    if GO_RUNTIME_SECTION not in sections:
        problems.append("THIRD-PARTY-NOTICES.txt lacks %s" % GO_RUNTIME_SECTION)
    for mod in sorted(deps):
        sec = NOTICE_SECTIONS.get(mod)
        if sec is None:
            problems.append("module %s is linked but has no license mapping (add its real license to THIRD-PARTY-NOTICES.txt and NOTICE_SECTIONS)" % mod)
        elif sec not in sections:
            problems.append("THIRD-PARTY-NOTICES.txt lacks %s for %s" % (sec, mod))
    report["modules"] = deps
    if target == "linux-amd64":
        dyn = elf_interp(binary)
        report["elf_pt_interp"] = dyn
        if dyn:
            problems.append("Linux binary has PT_INTERP (not static)")
    else:
        imps = pe_imports(binary)
        report["pe_imports"] = imps
        bad = [d for d in imps if d not in WINDOWS_SYSTEM_DLLS and not d.startswith("api-ms-win-")]
        if bad:
            problems.append("Windows binary imports non-system DLLs: %s" % ", ".join(bad))
    return report, problems


LICENSE_OVERRIDES = {}  # name -> path, from --license-file NAME=PATH


def libc_license(zig, target):
    """(name, relpath-in-zig, absolute path) of each libc license text, or die."""
    zig_dir = os.path.dirname(os.path.realpath(zig))
    found = []
    for name, candidates in LIBC_LICENSES[target]:
        if name in LICENSE_OVERRIDES:
            p = LICENSE_OVERRIDES[name]
            found.append((name, "--license-file " + os.path.basename(p), p))
            continue
        for rel in candidates:
            p = os.path.join(zig_dir, rel)
            if os.path.isfile(p):
                found.append((name, rel, p))
                break
        else:
            die("%s: license text of %s not found in the Zig installation (looked for %s under %s); "
                "packaging refused — give the original license file with --license-file %s=PATH "
                "(from the toolchain or the upstream source of the same version); it is not written by this script"
                % (target, name, ", ".join(candidates), zig_dir, name))
    return found


def write_zip(path, entries, mtime):
    """entries: [(name in zip, source path, mode)], deterministic order and timestamps."""
    dt = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).timetuple()[:6]
    dt = max(dt, (1980, 1, 1, 0, 0, 0))
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as z:
        for name, src, mode in sorted(entries):
            zi = zipfile.ZipInfo(name, dt)
            # Unix "made by": unzip on Linux applies the mode bits only then
            # (ZipInfo defaults to 0 = MS-DOS on Windows; without this the Linux
            # binary was unpacked 0644, not executable)
            zi.create_system = 3
            zi.external_attr = (mode & 0xFFFF) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(src, "rb") as f:
                z.writestr(zi, f.read())


def check_zip(path, entries):
    """Problems of a written package: every entry made by Unix (3) with the
    intended mode bits, and the same bytes as its source."""
    want = {name: (src, mode) for name, src, mode in entries}
    problems = []
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if sorted(i.filename for i in infos) != sorted(want):
            problems.append("zip entries differ from the planned contents")
        for i in infos:
            if i.filename not in want:
                continue
            src, mode = want[i.filename]
            if i.create_system != 3:
                problems.append("%s: create_system %d, want 3 (Unix)" % (i.filename, i.create_system))
            if (i.external_attr >> 16) & 0o177777 != mode:
                problems.append("%s: mode %o, want %o" % (i.filename, i.external_attr >> 16, mode))
            if hashlib.sha256(z.read(i)).hexdigest() != sha256_file(src):
                problems.append("%s: content differs from its source" % i.filename)
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--go", required=True, help="path of the go executable to use")
    ap.add_argument("--zig", required=True, help="path of the zig executable to use (C compiler for CGO)")
    ap.add_argument("--out", required=True, help="NEW staging directory (must not exist; outside the source tree)")
    ap.add_argument("--targets", default="windows-amd64,linux-amd64", help="comma-separated: windows-amd64,linux-amd64")
    ap.add_argument("--dry-run", action="store_true", help="validate and print the plan; build nothing, write nothing")
    ap.add_argument("--license-file", action="append", default=[], metavar="NAME=PATH",
                    help="original license text for a linked C runtime (musl, mingw-w64) when the Zig installation has none at the known paths")
    a = ap.parse_args()
    known = {n for v in LIBC_LICENSES.values() for n, _ in v}
    for spec in a.license_file:
        name, _, path = spec.partition("=")
        if name not in known or not os.path.isfile(path):
            die("--license-file %r: name must be one of %s and PATH an existing file" % (spec, ", ".join(sorted(known))))
        LICENSE_OVERRIDES[name] = os.path.abspath(path)

    targets = [t for t in a.targets.split(",") if t]
    for t in targets:
        if t not in TARGETS:
            die("unknown target %r" % t)
    go, zig = tool(a.go, "go"), tool(a.zig, "zig")
    out = check_out_dir(a.out)
    version = project_version()
    sections = notice_sections()
    for t in targets:
        for d in DOCS_COMMON + DOCS_PLATFORM[t]:
            if not os.path.isfile(os.path.join(ROOT, d)):
                die("documentation file missing: %s" % d)
    go_ver = run([go, "version"], env=tool_env()).strip()
    check_toolchain(go_ver)
    zig_ver = run([zig, "version"]).strip()
    files, tree_hash = source_tree()
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))  # 1980-01-01 unless given

    plan = []
    zig_cache = os.path.join(out, "zig-cache")
    for t in targets:
        env, shown, replaced = build_env(go, zig, t, zig_cache)
        out_bin = os.path.join(out, "build", t, TARGETS[t]["binary"])
        plan.append((t, env, shown, replaced, build_cmd(go, t, out_bin), out_bin))

    print("pentrail %s; source tree %d files, sha256 %s" % (version, len(files), tree_hash))
    print("go:  %s  (%s, sha256 %s)" % (go, go_ver, sha256_file(go)))
    print("zig: %s  (%s, sha256 %s)" % (zig, zig_ver, sha256_file(zig)))
    print("out: %s" % out)
    for t, env, shown, replaced, cmd, _ in plan:
        print("[%s] env %s" % (t, " ".join("%s=%s" % (k, shlex.quote(v)) for k, v in shown.items())))
        for k, v in sorted(replaced.items()):
            print("[%s] note: inherited %s=%s is replaced for this build" % (t, k, shlex.quote(v)))
        print("[%s] cmd %s" % (t, " ".join(shlex.quote(c) for c in cmd)))
    if a.dry_run:
        for t in targets:
            for name, rel, p in libc_license(zig, t):
                print("[%s] %s license: %s" % (t, name, rel))
        print("dry run: nothing built, nothing written")
        return

    os.makedirs(out)  # fails if it appeared meanwhile
    manifest = {
        "project": "pentrail", "version": version,
        "result": "in_progress",
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tree": {"root": ROOT, "files": len(files), "sha256": tree_hash,
                        "hash_rule": "sha256 over sorted lines 'relpath\\0sha256(file)\\n', dist/ and .git/ excluded"},
        "tools": {"go": {"path": go, "version": go_ver, "sha256": sha256_file(go)},
                  "zig": {"path": zig, "version": zig_ver, "sha256": sha256_file(zig)},
                  "python": sys.version.split()[0]},
        "zip_timestamp_epoch": mtime,
        "packages": {t: {"status": "pending"} for t in targets},
        "not_done": ["no signing", "no publication", "no tests run by this script: a successful build is not a test result"],
    }
    write_manifest(out, manifest)  # the attempt is on record before anything is built
    try:
        for t, env, shown, replaced, cmd, out_bin in plan:
            pkg = manifest["packages"][t]
            pkg.update({"status": "building", "build_env": shown, "inherited_env_replaced": replaced,
                        "build_command": cmd})
            write_manifest(out, manifest)
            try:
                pkg["go_env"] = json.loads(run([go, "env", "-json"], env=env))  # effective settings of this build
                os.makedirs(os.path.dirname(out_bin))
                pkg["build_output"] = run(cmd, env=env)
                pkg["binary"] = {"file": os.path.relpath(out_bin, out).replace(os.sep, "/"), "sha256": sha256_file(out_bin)}
                report, problems = verify_binary(go, t, out_bin, version, sections, private_paths(go, zig, out, pkg["go_env"]))
                pkg["checks"], pkg["problems"] = report, problems
                lic = libc_license(zig, t)
                entries = [("pentrail-%s-%s/%s" % (version, t, TARGETS[t]["binary"]), out_bin, 0o100755)]
                for d in DOCS_COMMON + DOCS_PLATFORM[t]:
                    entries.append(("pentrail-%s-%s/%s" % (version, t, d), os.path.join(ROOT, d), 0o100644))
                for name, rel, p in lic:
                    entries.append(("pentrail-%s-%s/licenses/%s-%s" % (version, t, name, os.path.basename(rel)), p, 0o100644))
                pkg["libc_licenses"] = [{"name": n, "source": r, "sha256": sha256_file(p)} for n, r, p in lic]
                pkg["contents"] = [{"name": n, "sha256": sha256_file(src)} for n, src, _ in sorted(entries)]
                if problems:
                    pkg["status"] = "checks_failed"
                    print("[%s] CHECKS FAILED — no package written:\n  %s" % (t, "\n  ".join(problems)))
                else:
                    zpath = os.path.join(out, "pentrail-%s-%s.zip" % (version, t))
                    write_zip(zpath, entries, mtime)
                    pkg["package"] = {"file": os.path.basename(zpath), "sha256": sha256_file(zpath)}
                    zproblems = check_zip(zpath, entries)
                    pkg["package_checks"] = {"unix_modes_and_contents": "ok" if not zproblems else "failed", "problems": zproblems}
                    if zproblems:
                        pkg["status"] = "checks_failed"
                        print("[%s] PACKAGE CHECKS FAILED:\n  %s" % (t, "\n  ".join(zproblems)))
                    else:
                        pkg["status"] = "packaged"
                        print("[%s] %s  sha256 %s" % (t, os.path.basename(zpath), pkg["package"]["sha256"]))
            except CommandFailed as e:
                pkg.update({"status": "failed", "error": str(e), "failed_command": e.cmd,
                            "exit_code": e.code, "command_output": e.output})
                print("[%s] FAILED: %s\n%s" % (t, e, e.output))
            except Fail as e:
                pkg.update({"status": "failed", "error": str(e)})
                print("[%s] FAILED: %s" % (t, e))
            if os.path.isfile(out_bin) and "binary" not in pkg:
                pkg["binary"] = {"file": os.path.relpath(out_bin, out).replace(os.sep, "/"), "sha256": sha256_file(out_bin)}
            write_manifest(out, manifest)
    finally:
        # also on an unexpected error or interruption: record what exists
        ok = all(manifest["packages"][t].get("status") == "packaged" for t in targets)
        manifest["result"] = "succeeded" if ok else "failed"
        manifest["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        write_manifest(out, manifest)
        sums = []
        for t in targets:
            p = manifest["packages"][t]
            if "binary" in p:
                sums.append("%s  %s\n" % (p["binary"]["sha256"], p["binary"]["file"]))
            if "package" in p:
                sums.append("%s  %s\n" % (p["package"]["sha256"], p["package"]["file"]))
        write_atomic(os.path.join(out, "SHA256SUMS"), "".join(sums))
        if manifest["result"] == "succeeded":
            try:
                write_public_buildinfo(out, manifest, private_paths(go, zig, out, {}))
            except Fail as e:
                manifest["result"] = "failed"
                manifest["public_buildinfo"] = "refused: %s" % e
                write_manifest(out, manifest)
                print("PUBLIC BUILD INFO REFUSED: %s" % e)
        print("manifest: %s (result: %s)" % (os.path.join(out, "MANIFEST.json"), manifest["result"]))
    if manifest["result"] != "succeeded":
        failed = ", ".join("%s=%s" % (t, manifest["packages"][t].get("status")) for t in targets)
        die("BUILD FAILED (%s); artifacts that were produced are listed in MANIFEST.json and SHA256SUMS" % failed)


def write_atomic(path, text):
    """Write a file of the staging directory: temporary name, flush, rename."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def private_paths(go, zig, out, go_env):
    """Local absolute paths that must not appear in published files."""
    p = {"source tree": ROOT, "output directory": out, "go tool": os.path.dirname(os.path.dirname(go)),
         "zig tool": os.path.dirname(zig), "home": os.path.expanduser("~")}
    for k in ("GOROOT", "GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR"):
        if go_env.get(k):
            p[k] = go_env[k]
    return {k: os.path.normpath(v) for k, v in p.items() if v and os.path.isabs(v) and os.path.normpath(v) not in ("/", "\\")}


ABSOLUTE_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/][^\s\"']+|(?<![\w.])/(?:home|root|users|tmp|var|usr|opt|mnt|private)/[^\s\"']*)")


def public_buildinfo(manifest, paths):
    """What can be published next to the packages: the manifest without local
    paths, environment dumps or compiler output. Raises Fail if anything that
    looks like an absolute path remains."""
    def scrub(v):
        if isinstance(v, str):
            for label, p in sorted(paths.items(), key=lambda kv: -len(kv[1])):
                for form in {p, p.replace("\\", "/"), p.replace("/", "\\")}:
                    v = re.sub(re.escape(form) + r"(?=[\\/\"' ]|$)", "<%s>" % label, v, flags=re.I)
            return v
        if isinstance(v, list):
            return [scrub(x) for x in v]
        if isinstance(v, dict):
            return {k: scrub(x) for k, x in v.items()}
        return v
    pub = {"project": manifest["project"], "version": manifest["version"], "result": manifest["result"],
           "source_tree": {k: manifest["source_tree"][k] for k in ("files", "sha256", "hash_rule")},
           "tools": {"go": {k: manifest["tools"]["go"][k] for k in ("version", "sha256")},
                     "zig": {k: manifest["tools"]["zig"][k] for k in ("version", "sha256")},
                     "python": manifest["tools"]["python"]},
           "zip_timestamp_epoch": manifest["zip_timestamp_epoch"], "not_done": manifest["not_done"], "packages": {}}
    for t, p in manifest["packages"].items():
        checks = dict(p.get("checks", {}))
        if "go_version_m" in checks:  # first line: the local file name of the binary
            lines = checks["go_version_m"].split("\n")
            lines[0] = "%s: %s" % (TARGETS[t]["binary"], lines[0].rsplit(": ", 1)[-1])
            checks["go_version_m"] = "\n".join(lines)
        pub["packages"][t] = scrub({k: p[k] for k in ("status", "build_env", "build_command", "binary", "package", "contents",
                                                       "libc_licenses", "package_checks", "problems") if k in p})
        pub["packages"][t]["checks"] = scrub(checks)
    text = json.dumps(pub, indent=2, sort_keys=True) + "\n"
    left = ABSOLUTE_PATH.findall(text)
    if left:
        raise Fail("public build info would contain absolute paths: %s" % ", ".join(sorted(set(left))[:5]))
    return text


def write_public_buildinfo(out, manifest, paths):
    write_atomic(os.path.join(out, "BUILDINFO-public.json"), public_buildinfo(manifest, paths))


def write_manifest(out, manifest):
    write_atomic(os.path.join(out, "MANIFEST.json"), json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def entry():
    try:
        main()
    except Fail as e:
        sys.stderr.write("build_release: ERROR: %s\n" % e)
        if isinstance(e, CommandFailed):
            sys.stderr.write(e.output)
        sys.exit(1)

if __name__ == "__main__":
    entry()
