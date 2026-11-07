# Session transport

The client in your terminal and the session server that owns the shell talk
over a local, versioned protocol. This page describes its behaviour and its
limits.

## Protocol

- Length-prefixed frames in both directions over a Unix socket (Linux) or a
  named pipe (Windows), both restricted to the current user.
- A `pentrail-session/5` handshake. Old clients and old session servers are
  incompatible: the client reports a handshake error or timeout instead of
  treating an old raw stream as success.
- Input and resize frames go through one serialized writer. Short writes are
  completed; a failed partial frame stops the writer instead of corrupting the
  stream.

## Order of persistence and output

The server's PTY loop commits each received chunk (and the encrypted
unfinished-line checkpoint) to the database **before** publishing it to the
clients. When the shell ends, the server drains its queues, ends the session,
imports finished tool files and closes the database before it sends the final
status to the client. Errors from these steps are included in that status.

A missing final status (end of stream, killed server, timeout or a client
disconnected for being slow) is reported by the client as **unknown evidence
completeness**; a disconnected window prints
`session disconnected before final capture status`. The session keeps
running and can be reattached with `pentrail attach`.

## Several clients and flow control

- Up to 16 clients can be attached to one session.
- Each client has a bounded output queue (128 chunks, normally up to about
  4 MiB).
- Exactly one client **paces** the session: the one that typed most recently
  (before any input, the first one attached). A slow pacing client slows the
  output like a real terminal — the PTY is not read and the shell's writes
  block.
- When another client sends input it becomes the pacer immediately, even if
  output is currently waiting for the old pacer; the old pacer becomes an
  observer.
- Observers never slow the session. An observer whose queue is full is
  disconnected; it can reattach.
- Registration and control requests never wait for client I/O.

## Timeouts and their limits

- A pacing client is disconnected when **one chunk** has waited 5 minutes for
  a free queue slot. This does not measure overall progress: a client that
  drains one frame every few minutes is not disconnected, and the session
  runs at its pace until someone types in another window.
- Each frame write has its own deadline.
- When the shell ends, the server waits at most 30 seconds for clients to
  drain queued output and the final status. A client that cannot drain in
  that time gets no final status and reports unknown completeness; the
  evidence itself is already committed.

## Signals

`SIGHUP` and `SIGTERM` to the client restore the terminal before it exits;
`SIGKILL` cannot be intercepted. `Ctrl+\` detaches successfully. End of input
on the client alone waits for the session result. Output produced before a
client attaches is not replayed to it.

## Not provided

- PTY takeover after the session server crashes (the server is a single point
  of failure).
- Recovery of the terminal screen on reattach.
- Per-byte acknowledgement to the shell or a power-loss guarantee.

## Updating

Keep the old executable to serve sessions that use an older protocol; do not
end them only to update. Start new sessions with the new executable.
