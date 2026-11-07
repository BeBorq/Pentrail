# Known limitations

Pentrail records what reaches the terminal. This page lists what it cannot
see or guarantee, so that you can judge how far the record can be relied on.

## What is captured

- **Only sessions started through Pentrail** are recorded: a `pentrail start`
  shell, or new terminals of a shell configured with `setup` while recording
  is enabled. Terminals that were already open, other applications and
  non-interactive invocations are not taken over. There is no system-wide
  capture.
- Not wrapped automatically: `cmd /C`, PowerShell `-Command`, `-File`,
  `-EncodedCommand`, `-NonInteractive` (and their abbreviations), a script
  given positionally, non-interactive Bash/Zsh scripts. `cmd /D` and
  PowerShell `-NoProfile` deliberately bypass the configuration. PowerShell
  ISE is not supported.
- **Output while recording is paused** (`pentrail off`) is never recorded, and
  a command that spans a pause is not stitched together from two periods.
- Output produced while no client is attached is recorded but not replayed to
  the next client; reattaching does not restore the full screen state.

## Splitting the record into commands

The terminal stream is recorded independently of the split into commands.
The split is derived from shell markers and is **auxiliary**; the **Full
session record** in the viewer is authoritative.

- **Bash**: with history disabled or ignored, or with non-standard shell
  settings, the command list may contain only parts of commands.
- Inside `ssh`, a subshell or another interactive program there are no
  markers, so there is no split; the output is in the full record.
- **Windows** (ConPTY) delivers a *rendered* terminal stream, not the
  programs' original output. Windows may reorder markers and screen refreshes.
  The output range of one command does not prove its completeness, and an
  observed command end does not guarantee that the whole typed line can be
  restored.
- **PowerShell** uses PSReadLine to learn the accepted command. Without it,
  only the full record is available.
- **CMD** recognizes simple entries at the prompt; history recall and complex
  editing can prevent a reliable reconstruction. A line typed or pasted
  while a program runs becomes a command only when CMD echoes it at the next
  prompt; otherwise it is counted as unconfirmed input (it may have been
  program input). If CMD exits without another prompt, the last command is
  marked "end not observed".
- Exit codes are shown only when they were observed; Pentrail never invents
  one.

## Durability

- Received output is committed to the database **before** it is shown on the
  screen, and an unfinished line is kept in an encrypted recovery buffer, so
  a crash of the recording process loses no committed data.
- Output that a program has not yet written, or that Pentrail has not yet
  received, cannot be recovered.
- The session server is a single point of failure. If it dies, the shell
  usually ends with it; what is restored is the recorded data, not the
  running command. There is no PTY takeover after a crash.
- Pentrail has been tested against process crashes, not certified against
  power loss, hardware failure or an operating-system crash.
- After a reboot, `pentrail on` must be run again before new terminals are
  recorded.

## Flow control

A slow attached client slows the session like a real terminal. Only the
client that typed most recently paces the output; other clients are
observers and are disconnected when their queue is full (they can
reattach). A pacing client that makes no progress for 5 minutes is
disconnected. Details: [SESSION-TRANSPORT.md](SESSION-TRANSPORT.md).

## Masking

Masking is rule-based and cannot recognize every secret. See
[DATA-PROTECTION.md](DATA-PROTECTION.md#limits-of-masking).

## Viewer

- Main reads give up after 15 seconds and offer **Try again**; on a very
  busy computer a retry may be needed.
- Optional reads shown inside the timeline (notes, imported tool files) are
  bounded at 10 seconds and then reported as unknown, which can delay the
  timeline by up to that long.
- Response validation checks the overall shape of the data (for example a
  list of objects; for the graph, usable node ids and edge endpoints), not
  every field.
- Saving an operator note has no timeout and is never retried automatically,
  so that a write whose outcome is unknown is never reported as saved. If a
  save hangs, the note stays *Saving*/*Not saved* and your text is kept;
  use **Retry**. The read of the notes write token that comes before a save
  is bounded (15 seconds); if it fails, nothing is sent and the note shows
  *Not saved* with **Retry**.
- The graph's preview of a command's output is limited to its first 64 KiB;
  the timeline shows the whole available output.
- Cleanup ticks are stored in the browser's local storage, so they are not
  shared between browsers or backed up with the database.
- Touch interaction has not been tested on a physical touch device.

## Platforms and testing

- Supported: Windows 10 1809+ and Windows 11 (x86-64), Linux x86-64. Other
  architectures and macOS are not built or tested.
- See [TESTING.md](TESTING.md) for which tests run on which platform and
  what has been checked only in headless browsers.

## Packages

- Release packages are **not code-signed**. Windows may warn about an
  unknown publisher. Verify the SHA-256 checksums from the release.
- Version 0.6.29-durable is a **release candidate**.
- There is no installer and no `uninstall` command; see
  [QUICKSTART.md](QUICKSTART.md#removing-automatic-capture).
- An update does not change sessions that are already running. Keep the old
  binary to serve old sessions; start new sessions with the new version.
