#!/usr/bin/env bash
# Smoke test for harscrub: exercises the real CLI end to end against the
# bundled example capture. No network, idempotent, runs from a clean
# checkout (after `npm install`). Prints "SMOKE OK" on success.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$(pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

# 1. Build (idempotent).
npm run build >/dev/null 2>&1 || fail "npm run build failed"
CLI="node $ROOT/dist/cli.js"
echo "[smoke] build ok"

# 2. --version matches package.json; --help documents every command.
PKG_VERSION="$(node -p "require('$ROOT/package.json').version")"
CLI_VERSION="$($CLI --version)"
[ "$CLI_VERSION" = "$PKG_VERSION" ] || fail "--version mismatch: $CLI_VERSION != $PKG_VERSION"
HELP="$($CLI --help)"
for word in scrub audit rules init --mode --salt --drop-content; do
  echo "$HELP" | grep -q -- "$word" || fail "--help missing $word"
done
echo "[smoke] --help/--version ok ($CLI_VERSION)"

# 3. Error handling: bad flags and bad input exit 2.
set +e
$CLI scrub x.har --modes hash >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "unknown flag should exit 2"; }
echo "not json" | $CLI scrub - >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "non-JSON stdin should exit 2"; }
echo '{"some":"json"}' | $CLI audit - >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "non-HAR JSON should exit 2"; }
set -e
echo "[smoke] error handling ok (exit 2)"

# 4. audit finds the planted secrets in the example capture and exits 1.
set +e
AUDIT="$($CLI audit examples/login.har)"; AUDIT_EXIT=$?
set -e
[ "$AUDIT_EXIT" -eq 1 ] || fail "audit on the dirty example should exit 1, got $AUDIT_EXIT"
for marker in "authorization" "query-param" "cookie" "body-key" "url-credentials" "pattern:slack-token"; do
  echo "$AUDIT" | grep -q "$marker" || fail "audit output missing $marker"
done
# Previews are truncated: the JWT's signature segment must never appear.
echo "$AUDIT" | grep -q "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" && fail "audit leaked a full JWT"
echo "[smoke] audit ok (exit 1, findings listed)"

# 5. scrub removes every planted secret and keeps the HAR valid.
$CLI scrub examples/login.har -q > "$WORKDIR/clean.har" || fail "scrub failed"
for secret in \
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
  "hunter2" \
  "s3cr3t-cl13nt-k3y" \
  "b1946ac92492d2347c6235b4d2611184" \
  "hk_4f3e2d1c0b9a87654321fedcba098765" \
  "xoxb-210987654321" \
  "ghp_EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0" \
  "one-time-9b8c7d6e5f" \
  "tr0ub4dor" \
  "ZXlKaGJHY2lPaUpJVXpJMU5pSX"; do
  grep -q "$secret" "$WORKDIR/clean.har" && fail "scrubbed output still contains: $secret"
done
node -e "
  const har = JSON.parse(require('fs').readFileSync('$WORKDIR/clean.har', 'utf8'));
  if (har.log.entries.length !== 5) throw new Error('entry count changed');
  new URL(har.log.entries[1].request.url);
  const b64 = har.log.entries[0].response.content;
  if (b64.encoding !== 'base64') throw new Error('base64 encoding lost');
  JSON.parse(Buffer.from(b64.text, 'base64').toString('utf8'));
" || fail "scrubbed HAR is not structurally intact"
grep -q "Demo User" "$WORKDIR/clean.har" || fail "benign body content was destroyed"
grep -q "cdn.example.test/assets/app.js?v=1.4.2" "$WORKDIR/clean.har" || fail "benign URL was rewritten"
echo "[smoke] scrub ok (secrets gone, HAR intact)"

# 6. A scrubbed capture audits clean, and re-scrubbing is a no-op.
$CLI audit "$WORKDIR/clean.har" >/dev/null || fail "audit on scrubbed output should exit 0"
$CLI scrub "$WORKDIR/clean.har" -q > "$WORKDIR/clean2.har" || fail "second scrub failed"
cmp -s "$WORKDIR/clean.har" "$WORKDIR/clean2.har" || fail "scrub is not idempotent"
echo "[smoke] idempotency ok"

# 7. hash mode: deterministic, and mirrors carry the same tag.
$CLI scrub examples/login.har -q --mode hash --salt demo > "$WORKDIR/hash1.har"
$CLI scrub examples/login.har -q --mode hash --salt demo > "$WORKDIR/hash2.har"
cmp -s "$WORKDIR/hash1.har" "$WORKDIR/hash2.har" || fail "hash mode is not deterministic"
TAGS="$(grep -o 'REDACTED:[0-9a-f]\{8\}' "$WORKDIR/hash1.har" | sort -u | wc -l)"
[ "$TAGS" -ge 5 ] || fail "expected several distinct hash tags, got $TAGS"
node -e "
  const har = JSON.parse(require('fs').readFileSync('$WORKDIR/hash1.har', 'utf8'));
  const req = har.log.entries[1].request;
  const inUrl = decodeURIComponent(req.url.split('access_token=')[1]);
  const inArray = req.queryString.find((q) => q.name === 'access_token').value;
  if (inUrl !== inArray) throw new Error(inUrl + ' != ' + inArray);
" || fail "hash tags differ between url and queryString mirrors"
echo "[smoke] hash mode ok (deterministic, mirror-consistent)"

# 8. remove mode drops carriers; --drop-content drops response bodies.
$CLI scrub examples/login.har -q --mode remove > "$WORKDIR/removed.har"
grep -qi '"authorization"' "$WORKDIR/removed.har" && fail "remove mode left the authorization header"
$CLI scrub examples/login.har -q --drop-content > "$WORKDIR/nobody.har"
grep -q "removed by harscrub" "$WORKDIR/nobody.har" || fail "--drop-content left no breadcrumb"
grep -q "Demo User" "$WORKDIR/nobody.har" && fail "--drop-content left a response body"
echo "[smoke] remove mode + --drop-content ok"

# 9. init + rules file: keep-list honored, report printed, rules listed.
(cd "$WORKDIR" && $CLI init) || fail "init failed"
[ -f "$WORKDIR/harscrub.json" ] || fail "init did not write harscrub.json"
node -e "
  const fs = require('fs');
  const rules = JSON.parse(fs.readFileSync('$WORKDIR/harscrub.json', 'utf8'));
  rules.cookies.keep.push('theme');
  fs.writeFileSync('$WORKDIR/harscrub.json', JSON.stringify(rules));
"
$CLI scrub "$ROOT/examples/login.har" --rules "$WORKDIR/harscrub.json" -q > "$WORKDIR/kept.har" \
  || fail "scrub with rules file failed"
grep -q "theme=dark" "$WORKDIR/kept.har" || fail "cookies.keep was not honored"
$CLI rules --rules "$WORKDIR/harscrub.json" | grep -q "jwt" || fail "rules listing missing jwt pattern"
$CLI scrub "$ROOT/examples/login.har" --report -q 2>"$WORKDIR/report.txt" >/dev/null
grep -q "RULE" "$WORKDIR/report.txt" || fail "--report printed no table"
echo "[smoke] init + rules file + --report ok"

# 10. stdin/stdout piping round-trip.
$CLI scrub - -q < examples/login.har | $CLI audit - >/dev/null \
  || fail "piped scrub | audit should exit 0"
echo "[smoke] stdin/stdout pipes ok"

echo "SMOKE OK"
