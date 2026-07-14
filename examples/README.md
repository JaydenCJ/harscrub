# harscrub examples

Two fixtures to try every command against. All commands below are run
from the repository root after `npm install && npm run build`; replace
`node dist/cli.js` with `harscrub` if you installed the package globally.

## Files

- `login.har` — a realistic five-entry capture of an OAuth login flow,
  deliberately full of planted (fake) secrets: a Bearer JWT that also
  appears in the query string and in a base64-encoded JSON response, a
  password grant in a form body (text *and* params mirror), session
  cookies in the `Cookie` header and the parsed arrays, an `x-api-key`
  header, Slack/GitHub tokens inside a JSON body, a one-time token in a
  `Location` redirect, and basic-auth credentials in a URL. One entry
  (the CDN asset) is completely clean and must survive byte-identical.
- `harscrub.json` — a team rules file: hash mode with a shared salt,
  an extra header glob, kept UI cookies and a custom token pattern.

## See what would leak

```bash
node dist/cli.js audit examples/login.har          # table, exit 1
node dist/cli.js audit examples/login.har --json   # machine-readable
```

## Scrub it

```bash
node dist/cli.js scrub examples/login.har -o clean.har
node dist/cli.js scrub examples/login.har --report -o clean.har   # + per-rule table
node dist/cli.js audit clean.har                   # exit 0: safe to attach
```

## Correlate without leaking

```bash
node dist/cli.js scrub examples/login.har --mode hash --salt team42 -o clean.har
grep -o 'REDACTED:[0-9a-f]*' clean.har | sort | uniq -c | sort -rn
```

The same session token gets the same tag everywhere — you can still
follow it across entries, but the secret itself is gone.

## Use the team rules file

```bash
node dist/cli.js scrub examples/login.har --rules examples/harscrub.json -o clean.har
node dist/cli.js rules --rules examples/harscrub.json
```

`theme` survives (kept), `x-internal-*` headers would be caught, and
the custom `acme-key` pattern joins the built-ins.
