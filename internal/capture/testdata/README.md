# Native Windows capture fixtures

These directories hold byte-exact recordings of synthetic `cmd.exe` sessions
made with ConPTY on a Windows test machine (`raw.bin`: the terminal output,
`frames.jsonl` and `trace.jsonl`: the pump's chunking and markers,
`commands.json`: what the recorder segmented, `screen.bin`: the rendered
screen, `result.txt`: the test outcome at the time). The tests in
`internal/capture/cmd_native_fixture_test.go` replay them on every platform.

Before publication, local paths in the recordings (user name and workspace
directories) were replaced with fictional values of exactly the same length, so
every byte offset and screen position is unchanged. `SHA256.json` lists the
hashes of the sanitized files. The marker tokens in the traces are test values.
