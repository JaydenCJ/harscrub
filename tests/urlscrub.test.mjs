// URL scrubbing: query params by name, tokens by shape, userinfo
// passwords — with everything else preserved byte-for-byte and the
// result still a strictly valid URL.
import test from "node:test";
import assert from "node:assert/strict";

import { scrubUrl } from "../dist/urlscrub.js";
import { buildRules } from "../dist/rules.js";
import { makeRedactor } from "../dist/placeholder.js";
import { JWT } from "./helpers.mjs";

const rules = buildRules();
const mask = makeRedactor("mask", "");
const scrub = (url, r = rules, red = mask) => scrubUrl(url, r, red);

test("sensitive query params are redacted, benign ones preserved verbatim", () => {
  const { url, findings } = scrub(
    "https://api.example.test/v1/items?page=2&access_token=tok-123&sort=asc",
  );
  assert.equal(url, "https://api.example.test/v1/items?page=2&access_token=%5BREDACTED%5D&sort=asc");
  assert.deepEqual(findings.map((f) => f.item), ["access_token"]);
  // Matching is case-insensitive and sees through percent-encoded names.
  const encoded = scrub("https://h.example.test/?Access%5FToken=abc");
  assert.ok(encoded.url.endsWith("Access%5FToken=%5BREDACTED%5D"), encoded.url);
});

test("the scrubbed URL still parses under the WHATWG URL parser", () => {
  const { url } = scrub(`https://h.example.test/cb?code=4/abc&state=xyz#frag`);
  const parsed = new URL(url);
  assert.equal(parsed.hash, "#frag");
  assert.equal(parsed.searchParams.get("code"), "[REDACTED]");
  assert.equal(parsed.searchParams.get("state"), "xyz");
});

test("JWTs hiding in non-sensitive params or the path are caught by pattern", () => {
  const inParam = scrub(`https://h.example.test/login?next=${JWT}`);
  assert.equal(inParam.findings[0].rule, "pattern:jwt");
  assert.ok(!inParam.url.includes(JWT.slice(0, 20)));
  const inPath = scrub(`https://h.example.test/verify/${JWT}/done?x=1`);
  assert.equal(inPath.findings[0].rule, "pattern:jwt");
  assert.equal(inPath.url, "https://h.example.test/verify/%5BREDACTED%5D/done?x=1");
  assert.doesNotThrow(() => new URL(inPath.url));
});

test("userinfo passwords are masked, the username survives", () => {
  const { url, findings } = scrub("ftp://backup:pa%24%24w0rd@files.example.test/x");
  assert.equal(url, "ftp://backup:%5BREDACTED%5D@files.example.test/x");
  assert.equal(findings[0].rule, "url-credentials");
  assert.equal(findings[0].item, "backup");
  assert.equal(findings[0].secret, "pa$$w0rd");
});

test("remove mode drops the parameter and the userinfo entirely", () => {
  const remover = makeRedactor("remove", "");
  const a = scrub("https://u:pw@h.example.test/?keep=1&token=abc", rules, remover);
  assert.equal(a.url, "https://h.example.test/?keep=1");
  // When every parameter goes, the dangling "?" goes with it.
  const b = scrub("https://h.example.test/path?token=abc", rules, remover);
  assert.equal(b.url, "https://h.example.test/path");
});

test("hash mode yields the same tag for the same decoded value", () => {
  const hasher = makeRedactor("hash", "");
  const a = scrub("https://h.example.test/?token=abc%20def", rules, hasher);
  const b = scrub("https://h.example.test/?token=abc+def", rules, hasher);
  // %20 and + decode to the same secret, so the tags must match.
  assert.equal(a.url.split("=")[1], b.url.split("=")[1]);
});

test("keep-listed params and custom additions are honored", () => {
  const custom = buildRules({
    queryParams: { add: ["ticket"], keep: ["code"] },
  });
  const { url, findings } = scrub(
    "https://h.example.test/?code=oauth-code&ticket=ST-12345",
    custom,
  );
  assert.ok(url.includes("code=oauth-code"), "kept param untouched");
  assert.ok(url.includes("ticket=%5BREDACTED%5D"), "added param scrubbed");
  assert.deepEqual(findings.map((f) => f.item), ["ticket"]);
});

test("URLs without secrets come back byte-identical", () => {
  const inputs = [
    "https://cdn.example.test/assets/app.js?v=1.4.2",
    "https://h.example.test/plain/path",
    "/relative/path?page=3",
    // Empty values and valueless flags carry nothing to redact.
    "https://h.example.test/?token=&debug",
  ];
  for (const input of inputs) {
    const { url, findings } = scrub(input);
    assert.equal(url, input);
    assert.equal(findings.length, 0);
  }
});

test("scrubbing is idempotent, including in hash mode", () => {
  const hasher = makeRedactor("hash", "");
  const once = scrub(`https://u:pw@h.example.test/?token=${JWT}`, rules, hasher);
  const twice = scrub(once.url, rules, hasher);
  assert.equal(twice.url, once.url);
  assert.equal(twice.findings.length, 0);
});
