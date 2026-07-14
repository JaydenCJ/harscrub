# Rule files and redaction semantics

This document is the contract for `harscrub.json`: what each field does,
how rules merge, and exactly what the engine rewrites. The starter file
written by `harscrub init` contains every field with its default value.

## Loading and precedence

1. `--rules <file>` names a rules file explicitly.
2. Otherwise `./harscrub.json` is auto-discovered (silence it with
   `--no-config`; a `rules from …` line on stderr tells you when a file
   was used).
3. CLI flags (`--mode`, `--salt`, `--drop-content`) override the file.

Merging is **additive**: `add` lists extend the built-in defaults and
`keep` lists punch explicit holes in them. A rules file can never
silently drop `authorization` from the header list — forgetting a
default while customizing would be the worst possible failure mode for
a scrubber. Validation is strict: unknown keys and wrong types are hard
errors (exit 2), because a typo like `"header"` for `"headers"` must
not produce a confidently wrong output file.

## Fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `mode` | `"mask" \| "hash" \| "remove"` | `"mask"` | how matched values are rewritten (see below) |
| `salt` | string | `""` | mixed into `hash` tags so common values cannot be dictionary-matched across unrelated reports |
| `headers.add` | string[] | `[]` | extra header names/globs to redact (request and response) |
| `headers.keep` | string[] | `[]` | header names/globs exempted from the merged list |
| `cookies.keep` | string[] | `[]` | cookie names/globs whose values survive (all other cookie values are always redacted) |
| `queryParams.add` / `.keep` | string[] | `[]` | same, for URL query parameter names |
| `bodyKeys.add` / `.keep` | string[] | `[]` | same, for JSON keys and form field names, matched at any nesting depth |
| `patterns.disable` | string[] | `[]` | built-in token detectors to switch off (names as shown by `harscrub rules`) |
| `patterns.custom` | `{name, regex, flags?}[]` | `[]` | extra detectors; `flags` may contain `imsu` (`g` is implied) |
| `dropContent` | boolean | `false` | delete every response body, leaving a `comment` breadcrumb |

Names are matched case-insensitively. A `*` in a name makes it a glob
anchored at both ends: `x-internal-*` matches `x-internal-auth` but not
`not-x-internal-auth`.

## Modes

- **mask** — every match becomes the fixed string `[REDACTED]`.
- **hash** — every match becomes `[REDACTED:xxxxxxxx]`, the first 8 hex
  chars of SHA-256(salt + newline + value). Deterministic: the same session token
  carries the same tag in the URL, the `queryString` array, the
  `Cookie` header and the body, so a reader can still correlate
  requests. Use a salt when sharing outside your team; a guessable
  value (like a four-digit PIN) can be brute-forced against an unsalted
  tag, so prefer `mask` for low-entropy secrets.
- **remove** — the carrying element is deleted outright: the header or
  cookie disappears, the query parameter is cut out of the URL and the
  array, the JSON key is dropped. Output is the least informative but
  the safest to publish.

All three modes are idempotent: scrubbing an already-scrubbed file
changes nothing, because placeholders are recognized and skipped.

## What the engine rewrites

HAR stores the same secret in several mirrors, and every mirror is
handled:

| Location | Treatment |
|---|---|
| `request.url` | query params by name; userinfo passwords; token patterns in path and query — with string surgery, never URL re-serialization |
| `request.queryString[]` | kept in lockstep with the URL |
| `Cookie` header + `request.cookies[]` | every cookie value (minus `cookies.keep`), separator layout preserved |
| `Set-Cookie` header + `response.cookies[]` | the `name=value` pair; attributes (`Path`, `HttpOnly`, …) survive |
| listed headers | value replaced; a recognized auth scheme prefix (`Bearer`, `Basic`, …) is kept for readability |
| unlisted headers | token-pattern scan (a JWT in `x-debug-info` is still caught) |
| `Location` / `Referer` / `redirectURL` | treated as URLs and query-scrubbed |
| `postData.text` + `postData.params[]` | JSON keys at any depth, form fields, or a raw pattern scan — both mirrors consistently |
| `response.content.text` | same body treatment; base64 bodies are decoded, scrubbed and re-encoded (binary bodies are detected and left alone) |

## Format preservation

The output must still load in DevTools and every HAR viewer, and must
diff cleanly against the input:

- Untouched entries, headers, params and bodies are byte-identical.
- JSON bodies keep their indentation style; compact stays compact.
- Placeholders inserted into URLs are percent-encoded, so the URL still
  parses strictly.
- Vendor fields (`_initiator`, `_resourceType`, …) pass through as-is.
- Sizes stay honest: a rewritten body gets a recomputed `bodySize` /
  `content.size`; rewritten headers set `headersSize: -1` ("unknown"
  per the HAR spec) rather than claim stale byte counts.
