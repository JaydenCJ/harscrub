# Contributing to harscrub

Issues, discussions and pull requests are all welcome — this project
aims to stay small, zero-dependency at runtime, and safe by default.

## Getting started

Requirements: Node.js >= 22.13 (for the stable `node:test` runner used by the suite).

```bash
git clone https://github.com/JaydenCJ/harscrub.git
cd harscrub
npm install            # installs typescript, the only devDependency
npm run build          # compile TypeScript to dist/
npm test               # build + 92 node:test tests
bash scripts/smoke.sh  # end-to-end CLI check against examples/
```

`scripts/smoke.sh` exercises the real CLI (audit exit codes, scrub in
all three modes, idempotency, hash-tag mirror consistency, rules files,
stdin/stdout pipes) against the bundled example capture and must print
`SMOKE OK`.

## Before you open a pull request

1. `npx tsc -p tsconfig.json --noEmit` — the tree must type-check clean (strict mode is enforced).
2. `npm test` — all tests must pass.
3. `bash scripts/smoke.sh` — must print `SMOKE OK`.
4. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the engine takes values, not file handles — only `cli.ts`
   touches the filesystem).
5. Changes to default rules or built-in patterns are security-relevant:
   explain in the PR what new false positives/negatives they can cause.

## Ground rules

- **No runtime dependencies.** The zero-dependency install is a core
  feature; adding one needs justification in the PR and will usually be
  declined.
- No network calls, ever — the tool reads and writes local files only,
  and a scrubber that phones home would defeat its own purpose.
- Determinism is API: same input, same rules, byte-identical output —
  no clocks, no randomness, no locale-dependent comparisons.
- Fail closed: a malformed rules file must abort (exit 2), never fall
  back to weaker rules; placeholders must never be re-redacted.
- New token patterns must anchor on a structural prefix, not entropy
  guesses — false positives corrupt the capture people are debugging.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include: `harscrub --version` output, the exact command line,
your rules file (if any), and a *minimal, already-scrubbed* HAR that
reproduces the problem — never attach a raw capture to a public issue;
that is the exact accident this tool exists to prevent.

## Security

Do not open public issues for security problems (e.g. a value class the
default rules fail to redact); use GitHub private vulnerability
reporting on this repository instead.
