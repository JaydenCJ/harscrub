# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-12

### Added

- `harscrub scrub`: rule-driven redaction over every HAR mirror — the
  raw `Cookie`/`Set-Cookie` headers *and* the parsed cookie arrays, the
  URL *and* the `queryString` array, `postData.text` *and* `params` —
  plus `Location`/`Referer`/`redirectURL` treated as URLs, and response
  bodies including base64-encoded JSON (decoded, scrubbed, re-encoded;
  binary bodies detected and left alone).
- Three redaction modes: `mask` (`[REDACTED]`), `hash` (deterministic
  salted `[REDACTED:xxxxxxxx]` tags — the same secret carries the same
  tag in every mirror, so requests stay correlatable), and `remove`
  (delete the carrying header/cookie/param/key outright). All modes are
  idempotent: re-scrubbing a scrubbed file changes nothing.
- Default rule set: 23 credential header names, 27 query parameter
  names, 24 body keys (matched at any JSON depth), all cookie values,
  and 14 built-in token patterns (JWT, Bearer/Basic credentials, AWS,
  GitHub, GitLab, Slack, Stripe, Google, SendGrid, npm, sk- family,
  PEM private key blocks).
- `harscrub.json` rules files: additive `add`/`keep` lists with `*`
  globs, pattern disabling, custom `{name, regex}` detectors, mode/salt
  defaults — strictly validated (unknown keys are fatal), auto-discovered
  in the working directory, explicit via `--rules`.
- `harscrub audit`: CI-gate listing of what would be redacted with
  truncated previews, exit code 1 on findings, `--json` for machines.
- `harscrub rules` (effective rule set, text or JSON) and
  `harscrub init` (starter rules file).
- Format preservation: untouched entries byte-identical, JSON bodies
  keep their indentation, URLs edited by string surgery with
  percent-encoded placeholders, vendor `_fields` passed through, sizes
  recomputed (`bodySize`, `content.size`) or marked unknown
  (`headersSize: -1`) instead of left stale.
- Script-friendly CLI: stdin/stdout piping, `-o`/`--in-place`,
  `--report` per-rule summary table, `--quiet`, `--drop-content`, and
  shared exit codes (0 ok / 1 audit findings / 2 usage or input error).
- Public programmatic API (`scrubHar`, `auditHar`, `buildRules`,
  `scanText`, `scrubUrl`, `scrubBodyText`, …) with type declarations.
- Test suite: 92 node:test tests (unit + CLI integration in fresh temp
  dirs) and an end-to-end `scripts/smoke.sh` against the bundled
  example capture.

[0.1.0]: https://github.com/JaydenCJ/harscrub/releases/tag/v0.1.0
