# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability** (a private
security advisory). Do not open a public issue for a vulnerability.

Include the Pentrail version (`pentrail --help` prints it), the operating
system and shell, and steps to reproduce. Use **synthetic data only**: never
attach a real database, backup, report, log file or terminal output from a
real engagement.

There is no paid support or guaranteed response time. Reports are handled on
a best-effort basis by the maintainers.

## Supported versions

Only the newest published version receives fixes. All versions so far are
release candidates.

## Scope

In scope, for example:

- reading the database, the key or the viewer's data from another local user
  account or from the network;
- a web page in the browser reading or changing viewer data (CSRF, DNS
  rebinding, cross-origin reads);
- a recognized secret format that is stored unmasked, or masking that can be
  bypassed in a way the documentation says is covered;
- loss of committed data or a false "complete" status after a crash;
- unsafe file handling (following links, overwriting files, wrong
  permissions).

Out of scope, as described in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md):

- attacks by processes of the same user account or by an administrator;
- secrets without a recognizable label or format (masking is heuristic; see
  [docs/DATA-PROTECTION.md](docs/DATA-PROTECTION.md));
- the absence of code signing.

## Intended use

Pentrail records your own terminal sessions. Use it only on systems and in
engagements you are authorized to work on, and keep the database, backups
and reports confidential.
