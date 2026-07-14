// Built-in token detectors: each pattern must catch its credential
// format and must NOT fire on lookalike prose — false positives in a
// scrubber corrupt the capture people are trying to debug.
import test from "node:test";
import assert from "node:assert/strict";

import { BUILTIN_PATTERNS, compileCustomPattern, scanText } from "../dist/patterns.js";
import { makeRedactor } from "../dist/placeholder.js";
import { JWT } from "./helpers.mjs";

const mask = makeRedactor("mask", "");
const scan = (text) => scanText(text, BUILTIN_PATTERNS, mask);

test("jwt: three base64url segments are caught, prose with dots is not", () => {
  const { text, hits } = scan(`token=${JWT} rest`);
  assert.equal(text, "token=[REDACTED] rest");
  assert.deepEqual(hits.map((h) => h.pattern), ["jwt"]);
  assert.equal(scan("see e.g. section 2.3.1 for details").hits.length, 0);
});

test("bearer: scheme survives, credential is replaced, prose is spared", () => {
  const { text, hits } = scan("Authorization: Bearer abcdefghij0123456789");
  assert.equal(text, "Authorization: Bearer [REDACTED]");
  assert.equal(hits[0].pattern, "bearer-token");
  assert.equal(hits[0].secret, "abcdefghij0123456789");
  // "Bearer of bad news" must not be mangled — the credential charset
  // requires at least 16 token characters.
  assert.equal(scan("the bearer of bad news").hits.length, 0);
});

test("basic: base64 credentials after the scheme are replaced", () => {
  const { text, hits } = scan("Basic ZGVtbzpodW50ZXIy");
  assert.equal(text, "Basic [REDACTED]");
  assert.equal(hits[0].pattern, "basic-credentials");
});

test("aws and google keys: exact prefix + tail length, lookalikes spared", () => {
  const { text, hits } = scan("key=AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE");
  assert.equal(text, "key=[REDACTED] and [REDACTED]");
  assert.equal(hits.length, 2);
  assert.equal(scan("AKIA123").hits.length, 0, "too short: not a key");
  const google = "AIza" + "A".repeat(35);
  assert.equal(scan(google).hits[0].pattern, "google-api-key");
  assert.equal(scan("AIza" + "A".repeat(10)).hits.length, 0);
});

test("aws secret keys: caught when anchored by their key name, any case", () => {
  const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  // .env style, JSON style, uppercase env-var style — all anchored forms.
  for (const line of [
    `aws_secret=${secret}`,
    `AWS_SECRET_ACCESS_KEY=${secret}`,
    `"aws_secret_access_key": "${secret}"`,
  ]) {
    const { text, hits } = scan(line);
    assert.deepEqual(hits.map((h) => h.pattern), ["aws-secret-key"], line);
    assert.equal(hits[0].secret, secret);
    assert.ok(!text.includes(secret), "secret must be gone");
    assert.ok(/aws.secret/i.test(text), "the key-name anchor survives");
  }
});

test("aws secret keys: a bare 40-char string without the anchor is spared", () => {
  // Entropy-only guesses are forbidden by design — a 40-char base64-ish
  // string with no key-name context could be an ETag or a git SHA+tail.
  const bare = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  assert.equal(scan(`payload=${bare}`).hits.length, 0);
  // Wrong value length must not match either.
  assert.equal(scan("aws_secret=tooShort123").hits.length, 0);
});

test("github tokens: classic and fine-grained prefixes", () => {
  const classic = "ghp_EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0";
  const fine = "github_pat_AAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAA";
  const { hits } = scan(`${classic} ${fine}`);
  assert.deepEqual(hits.map((h) => h.pattern), ["github-token", "github-token"]);
});

test("slack, stripe, gitlab, sendgrid, npm and sk- family keys", () => {
  const samples = {
    "slack-token": "xoxb-210987654321-abcdefghijkl",
    "stripe-key": "sk_test_abcdefghijklmnop0123",
    "gitlab-token": "glpat-abcdefghij0123456789",
    "sendgrid-key": "SG.abcdefghijklmnop.qrstuvwxyz0123456789",
    "npm-token": "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "sk-api-key": "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  for (const [name, value] of Object.entries(samples)) {
    const { hits } = scan(`x=${value};`);
    assert.deepEqual(hits.map((h) => h.pattern), [name], `expected ${name} to fire`);
  }
});

test("private key blocks are redacted whole, including the body", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow…lines…\n-----END RSA PRIVATE KEY-----";
  const { text, hits } = scan(`before\n${pem}\nafter`);
  assert.equal(hits[0].pattern, "private-key");
  assert.ok(!text.includes("MIIEow"));
  assert.ok(text.includes("before"), "surrounding text survives");
});

test("placeholders are never re-matched, and hash tags stay distinct", () => {
  const first = scan(`Bearer abcdefghij0123456789 and ${JWT}`);
  const second = scanText(first.text, BUILTIN_PATTERNS, mask);
  assert.equal(second.hits.length, 0);
  assert.equal(second.text, first.text);
  // In hash mode two different tokens inside one string get two tags.
  const hasher = makeRedactor("hash", "");
  const { text } = scanText(
    "a=AKIAIOSFODNN7EXAMPLE b=AKIAI44QH8DHBEXAMPLE",
    BUILTIN_PATTERNS,
    hasher,
  );
  const tags = [...text.matchAll(/\[REDACTED:([0-9a-f]{8})\]/g)].map((m) => m[1]);
  assert.equal(tags.length, 2);
  assert.notEqual(tags[0], tags[1]);
});

test("multiple tokens in one string are each replaced", () => {
  const { text, hits } = scan(`a=${JWT}&b=AKIAIOSFODNN7EXAMPLE`);
  assert.equal(hits.length, 2);
  assert.equal(text, "a=[REDACTED]&b=[REDACTED]");
});

test("custom patterns are validated at compile time and applied in scans", () => {
  const ok = compileCustomPattern({ name: "acme", regex: "acme_[a-z0-9]{8}" });
  assert.equal(ok.name, "acme");
  assert.equal(ok.builtin, false);
  assert.throws(() => compileCustomPattern({ name: "bad", regex: "([" }), /invalid regex/);
  assert.throws(() => compileCustomPattern({ name: "bad", regex: "x", flags: "g" }), /flags/);
  const patterns = [...BUILTIN_PATTERNS, ok];
  const { text, hits } = scanText("id=acme_a1b2c3d4 done", patterns, mask);
  assert.equal(text, "id=[REDACTED] done");
  assert.deepEqual(hits.map((h) => h.pattern), ["acme"]);
});
