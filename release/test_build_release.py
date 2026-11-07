#!/usr/bin/env python3
"""Offline tests of the publication guards in build_release.py (no Go, no Zig).

Run: python3 release/test_build_release.py
"""
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_release as br  # noqa: E402

WIN = {"source tree": r"C:\Users\someone\work\Pentrail", "output directory": r"D:\stage\pentrail-out",
       "go tool": r"C:\Users\someone\toolchain\go1.27.3\go", "zig tool": r"C:\Users\someone\toolchain\zig-0.13.0",
       "home": r"C:\Users\someone", "GOMODCACHE": r"C:\Users\someone\go\pkg\mod"}


def manifest(paths):
    go_exe = paths["go tool"] + r"\bin\go.exe"
    zig = paths["zig tool"] + r"\zig.exe"
    out = paths["output directory"]
    return {
        "project": "pentrail", "version": "0.6.28-durable", "result": "succeeded",
        "source_tree": {"root": paths["source tree"], "files": 3, "sha256": "ab" * 32, "hash_rule": "rule"},
        "tools": {"go": {"path": go_exe, "version": "go version go1.27.3 windows/amd64", "sha256": "cd" * 32},
                  "zig": {"path": zig, "version": "0.13.0", "sha256": "ef" * 32}, "python": "3.12.0"},
        "zip_timestamp_epoch": 315532800, "not_done": ["no signing"],
        "packages": {"windows-amd64": {
            "status": "packaged",
            "build_env": {"CC": '"%s" cc -target x86_64-windows-gnu' % zig, "ZIG_GLOBAL_CACHE_DIR": out + r"\zig-cache"},
            "build_command": [go_exe, "build", "-o", out + r"\build\windows-amd64\pentrail.exe", "./cmd/pentrail"],
            "go_env": {"GOROOT": paths["go tool"], "GOMODCACHE": paths["GOMODCACHE"]},
            "build_output": "warning in " + paths["GOMODCACHE"] + r"\x\sqlite3.c",
            "checks": {"go_version_m": out + r"\build\windows-amd64\pentrail.exe: go1.27.3" + "\n\tpath\tgithub.com/BeBorq/Pentrail/cmd/pentrail\n"},
            "binary": {"file": "build/windows-amd64/pentrail.exe", "sha256": "11" * 32},
            "package": {"file": "pentrail-0.6.28-durable-windows-amd64.zip", "sha256": "22" * 32},
            "contents": [{"name": "pentrail-0.6.28-durable-windows-amd64/README.md", "sha256": "33" * 32}],
            "libc_licenses": [{"name": "mingw-w64", "source": "lib/libc/mingw/COPYING", "sha256": "44" * 32}],
            "problems": []}},
    }


class PublicBuildInfo(unittest.TestCase):
    def test_no_local_paths_environment_or_compiler_output(self):
        text = br.public_buildinfo(manifest(WIN), WIN)
        low = text.lower()
        for p in WIN.values():
            self.assertNotIn(p.lower(), low)
            self.assertNotIn(p.replace("\\", "/").lower(), low)
        self.assertNotIn("someone", low)
        pub = json.loads(text)
        pkg = pub["packages"]["windows-amd64"]
        self.assertNotIn("go_env", pkg)
        self.assertNotIn("build_output", pkg)
        self.assertNotIn("root", pub["source_tree"])
        self.assertNotIn("path", pub["tools"]["go"])
        self.assertTrue(pkg["checks"]["go_version_m"].startswith("pentrail.exe: go1.27.3\n"))
        self.assertIn("<output directory>", " ".join(pkg["build_command"]))
        self.assertEqual(pkg["package"]["sha256"], "22" * 32)

    def test_unknown_absolute_path_is_refused(self):
        m = manifest(WIN)
        m["packages"]["windows-amd64"]["problems"] = [r"see E:\private\notes.txt"]
        with self.assertRaises(br.Fail):
            br.public_buildinfo(m, WIN)
        m = manifest(WIN)
        m["packages"]["windows-amd64"]["problems"] = ["see /home/someone/notes.txt"]
        with self.assertRaises(br.Fail):
            br.public_buildinfo(m, WIN)

    def test_linux_paths(self):
        lin = {"source tree": "/home/someone/src/Pentrail", "output directory": "/srv/stage/out",
               "go tool": "/home/someone/sdk/go", "zig tool": "/opt/zig-0.13.0", "home": "/home/someone",
               "GOMODCACHE": "/home/someone/go/pkg/mod"}
        m = manifest(lin)
        m["packages"]["windows-amd64"]["build_command"] = ["/home/someone/sdk/go/bin/go", "build", "-o", "/srv/stage/out/build/x"]
        text = br.public_buildinfo(m, lin)
        self.assertNotIn("someone", text)
        self.assertNotIn("/srv/stage", text)


class BinaryPathScan(unittest.TestCase):
    def test_detects_local_paths_in_any_separator_and_case(self):
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "bin")
            with open(b, "wb") as f:
                f.write(b"\x00runtime\x00c:/users/someone/go/pkg/mod/github.com/x/sqlite3.c\x00")
            self.assertEqual(br.private_path_hits(b, WIN), ["GOMODCACHE", "home"])
            with open(b, "wb") as f:
                f.write(b"\x00crypto/x509/root.go\x00os/root_unix.go\x00pentrail 0.6.28-durable\x00")
            self.assertEqual(br.private_path_hits(b, WIN), [])
            self.assertEqual(br.private_path_hits(b, {"home": "/root"}), [], "/root matched os/root_unix.go")
            with open(b, "wb") as f:
                f.write(b"\x00/root/go/pkg/mod/github.com/x\x00")
            self.assertEqual(br.private_path_hits(b, {"home": "/root"}), ["home"])


def broken_links(files):
    """Relative Markdown links and images of `files` (paths relative to the
    source root) whose target is not in `files`."""
    present, bad = set(files), []
    for f in files:
        if not f.endswith(".md"):
            continue
        with open(os.path.join(br.ROOT, f), encoding="utf-8") as fh:
            text = re.sub(r"```.*?```", "", fh.read(), flags=re.S)
        for m in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)\)", text):
            target = m.group(1)
            if re.match(r"[a-z]+:", target) or target.startswith("#"):
                continue
            path = os.path.normpath(os.path.join(os.path.dirname(f), target.split("#")[0])).replace(os.sep, "/")
            if path not in present:
                bad.append("%s -> %s" % (f, target))
    return bad


class Toolchain(unittest.TestCase):
    def test_release_go_must_match_go_mod_toolchain(self):
        want = br.required_toolchain()
        self.assertEqual(want, "go1.27.3")
        br.check_toolchain("go version go1.27.3 windows/amd64")
        for other in ("go version go1.24.7 windows/amd64", "go version go1.27.2 linux/amd64", "garbage"):
            with self.assertRaises(br.Fail):
                br.check_toolchain(other)


class Packaging(unittest.TestCase):
    def test_links_resolve_inside_each_package(self):
        for t in br.TARGETS:
            self.assertEqual(broken_links(br.DOCS_COMMON + br.DOCS_PLATFORM[t]), [], t)

    def test_links_resolve_in_the_repository(self):
        files = []
        for d, dirs, names in os.walk(br.ROOT):
            dirs[:] = [x for x in dirs if x not in (".git", "dist", "__pycache__")]
            files += [os.path.relpath(os.path.join(d, n), br.ROOT).replace(os.sep, "/") for n in names]
        self.assertEqual(broken_links(files), [])

    def test_every_packaged_document_exists(self):
        for t in br.TARGETS:
            for d in br.DOCS_COMMON + br.DOCS_PLATFORM[t]:
                self.assertTrue(os.path.isfile(os.path.join(br.ROOT, d)), d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
