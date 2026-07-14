// The scrub engine: every HAR mirror (header ↔ parsed array, url ↔
// queryString, text ↔ params) must be cleaned consistently, sizes must
// stay honest, vendor fields must survive, and the whole thing must be
// idempotent.
import test from "node:test";
import assert from "node:assert/strict";

import { scrubHar, auditHar, scrubCookieHeaderValue } from "../dist/scrub.js";
import { buildRules } from "../dist/rules.js";
import { makeRedactor } from "../dist/placeholder.js";
import { JWT, makeEntry, makeHar } from "./helpers.mjs";

const rules = buildRules();

test("authorization headers keep their scheme; the input HAR is never mutated", () => {
  const har = makeHar([
    makeEntry({
      request: {
        headers: [
          { name: "Authorization", value: `Bearer ${JWT}` },
          { name: "accept", value: "application/json" },
        ],
      },
    }),
  ]);
  const before = JSON.stringify(har);
  const { har: out, findings } = scrubHar(har, rules);
  assert.equal(JSON.stringify(har), before, "scrubHar works on a deep copy");
  const auth = out.log.entries[0].request.headers.find((h) => h.name === "Authorization");
  assert.equal(auth.value, "Bearer [REDACTED]");
  assert.equal(findings[0].rule, "header");
  assert.equal(findings[0].item, "authorization");
  assert.ok(!findings[0].preview.includes(JWT.slice(-20)), "preview is truncated");
});

test("cookie header and the parsed cookies array are scrubbed consistently", () => {
  const hashRules = buildRules({ mode: "hash" });
  const har = makeHar([
    makeEntry({
      request: {
        headers: [{ name: "cookie", value: "sid=abc123; theme=dark" }],
        cookies: [
          { name: "sid", value: "abc123" },
          { name: "theme", value: "dark" },
        ],
      },
    }),
  ]);
  const { har: out } = scrubHar(har, hashRules);
  const req = out.log.entries[0].request;
  const headerValue = req.headers[0].value;
  const sidTag = req.cookies.find((c) => c.name === "sid").value;
  // The same secret must carry the same hash tag in both mirrors.
  assert.ok(headerValue.includes(`sid=${sidTag}`), `${headerValue} vs ${sidTag}`);
  assert.match(sidTag, /^\[REDACTED:[0-9a-f]{8}\]$/);
  // The keep-list applies to the header string and the array alike.
  const keepRules = buildRules({ cookies: { keep: ["theme"] } });
  const { har: kept } = scrubHar(har, keepRules);
  const keptReq = kept.log.entries[0].request;
  assert.equal(keptReq.headers[0].value, "sid=[REDACTED]; theme=dark");
  assert.equal(keptReq.cookies.find((c) => c.name === "theme").value, "dark");
});

test("scrubCookieHeaderValue preserves separator spacing and reports names", () => {
  const seen = [];
  const out = scrubCookieHeaderValue(
    "a=1;  b=2; c=",
    rules,
    makeRedactor("mask", ""),
    (name, secret) => seen.push([name, secret]),
  );
  assert.equal(out, "a=[REDACTED];  b=[REDACTED]; c=");
  assert.deepEqual(seen, [["a", "1"], ["b", "2"]]);
});

test("set-cookie values are masked but attributes survive", () => {
  const har = makeHar([
    makeEntry({
      response: {
        headers: [
          { name: "set-cookie", value: "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax" },
        ],
        cookies: [{ name: "sid", value: "abc123", path: "/", httpOnly: true }],
      },
    }),
  ]);
  const { har: out } = scrubHar(har, rules);
  const resp = out.log.entries[0].response;
  assert.equal(resp.headers[0].value, "sid=[REDACTED]; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(resp.cookies[0].value, "[REDACTED]");
  assert.equal(resp.cookies[0].httpOnly, true, "cookie metadata survives");
});

test("request url and queryString array stay in lockstep", () => {
  const hashRules = buildRules({ mode: "hash" });
  const har = makeHar([
    makeEntry({
      request: {
        url: "https://api.example.test/v1/me?access_token=tok-123&page=1",
        queryString: [
          { name: "access_token", value: "tok-123" },
          { name: "page", value: "1" },
        ],
      },
    }),
  ]);
  const { har: out } = scrubHar(har, hashRules);
  const req = out.log.entries[0].request;
  const arrayValue = req.queryString.find((q) => q.name === "access_token").value;
  assert.equal(decodeURIComponent(req.url.split("access_token=")[1].split("&")[0]), arrayValue);
  assert.equal(req.queryString.find((q) => q.name === "page").value, "1");
});

test("postData text and params mirrors are both cleaned", () => {
  const har = makeHar([
    makeEntry({
      request: {
        method: "POST",
        bodySize: 26,
        postData: {
          mimeType: "application/x-www-form-urlencoded",
          text: "user=demo&password=hunter2",
          params: [
            { name: "user", value: "demo" },
            { name: "password", value: "hunter2" },
          ],
        },
      },
    }),
  ]);
  const { har: out } = scrubHar(har, rules);
  const pd = out.log.entries[0].request.postData;
  assert.equal(pd.text, "user=demo&password=%5BREDACTED%5D");
  assert.equal(pd.params.find((p) => p.name === "password").value, "[REDACTED]");
  assert.equal(pd.params.find((p) => p.name === "user").value, "demo");
});

test("rewritten bodies get a recomputed bodySize; rewritten headers go unknown", () => {
  const text = "password=hunter2";
  const har = makeHar([
    makeEntry({
      request: {
        method: "POST",
        bodySize: text.length,
        headersSize: 222,
        headers: [{ name: "x-api-key", value: "k-123456" }],
        postData: { mimeType: "application/x-www-form-urlencoded", text },
      },
    }),
  ]);
  const { har: out } = scrubHar(har, rules);
  const req = out.log.entries[0].request;
  assert.equal(req.bodySize, req.postData.text.length);
  assert.equal(req.headersSize, -1, "rewritten headers cannot claim the original byte size");
});

test("untouched entries stay deep-equal, sizes and vendor fields included", () => {
  const entry = makeEntry({
    request: { url: "https://cdn.example.test/app.js?v=1.2" },
    response: { content: { size: 10, mimeType: "text/plain", text: "плain body" } },
  });
  entry._resourceType = "script";
  const har = makeHar([entry]);
  const { har: out, findings } = scrubHar(har, rules);
  assert.equal(findings.length, 0);
  assert.deepEqual(out, har);
});

test("base64 JSON bodies are decoded, scrubbed, re-encoded, size updated", () => {
  const body = JSON.stringify({ access_token: "tok-1", ok: true });
  const har = makeHar([
    makeEntry({
      response: {
        content: {
          size: body.length,
          mimeType: "application/json",
          text: Buffer.from(body, "utf8").toString("base64"),
          encoding: "base64",
        },
      },
    }),
  ]);
  const { har: out, findings } = scrubHar(har, rules);
  const content = out.log.entries[0].response.content;
  assert.equal(content.encoding, "base64", "encoding is preserved");
  const decoded = JSON.parse(Buffer.from(content.text, "base64").toString("utf8"));
  assert.equal(decoded.access_token, "[REDACTED]");
  assert.equal(content.size, Buffer.byteLength(JSON.stringify(decoded)));
  assert.equal(findings[0].location, "response.content");
});

test("binary base64 bodies are left byte-identical", () => {
  // 4 raw bytes that are not valid UTF-8 text.
  const binary = Buffer.from([0xff, 0xd8, 0xff, 0xe0]).toString("base64");
  const har = makeHar([
    makeEntry({
      response: {
        content: { size: 4, mimeType: "image/jpeg", text: binary, encoding: "base64" },
      },
    }),
  ]);
  const { har: out, findings } = scrubHar(har, rules);
  assert.equal(out.log.entries[0].response.content.text, binary);
  assert.equal(findings.length, 0);
});

test("dropContent removes every body and leaves a comment breadcrumb", () => {
  const dropRules = buildRules({ dropContent: true });
  const har = makeHar([
    makeEntry({
      response: {
        content: { size: 12, mimeType: "text/html", text: "<html></html>" },
      },
    }),
  ]);
  const { har: out, findings } = scrubHar(har, dropRules);
  const content = out.log.entries[0].response.content;
  assert.equal(content.text, undefined);
  assert.match(content.comment, /removed by harscrub/);
  assert.equal(findings[0].rule, "drop-content");
});

test("location header and redirectURL are query-scrubbed as URLs", () => {
  const har = makeHar([
    makeEntry({
      response: {
        status: 302,
        headers: [{ name: "location", value: "https://h.example.test/cb?token=one-time-1" }],
        redirectURL: "https://h.example.test/cb?token=one-time-1",
      },
    }),
  ]);
  const { har: out, findings } = scrubHar(har, rules);
  const resp = out.log.entries[0].response;
  assert.ok(resp.headers[0].value.endsWith("token=%5BREDACTED%5D"));
  assert.ok(resp.redirectURL.endsWith("token=%5BREDACTED%5D"));
  const locations = findings.map((f) => f.location).sort();
  assert.deepEqual(locations, ["response.headers", "response.redirectURL"]);
});

test("tokens in unlisted custom headers are caught by pattern scan", () => {
  const har = makeHar([
    makeEntry({
      request: { headers: [{ name: "x-debug-info", value: `jwt=${JWT}` }] },
    }),
  ]);
  const { har: out, findings } = scrubHar(har, rules);
  assert.equal(out.log.entries[0].request.headers[0].value, "jwt=[REDACTED]");
  assert.equal(findings[0].rule, "pattern:jwt");
});

test("remove mode deletes headers, cookies and params outright", () => {
  const removeRules = buildRules({ mode: "remove" });
  const har = makeHar([
    makeEntry({
      request: {
        url: "https://h.example.test/?token=t&keep=1",
        headers: [
          { name: "authorization", value: "Bearer abcdef" },
          { name: "cookie", value: "sid=1" },
          { name: "accept", value: "*/*" },
        ],
        queryString: [
          { name: "token", value: "t" },
          { name: "keep", value: "1" },
        ],
        cookies: [{ name: "sid", value: "1" }],
      },
    }),
  ]);
  const { har: out } = scrubHar(har, removeRules);
  const req = out.log.entries[0].request;
  assert.deepEqual(req.headers.map((h) => h.name), ["accept"]);
  assert.deepEqual(req.queryString, [{ name: "keep", value: "1" }]);
  assert.deepEqual(req.cookies, []);
  assert.equal(req.url, "https://h.example.test/?keep=1");
});

test("vendor extension fields survive even when the entry is rewritten", () => {
  const entry = makeEntry({
    request: { headers: [{ name: "authorization", value: "Bearer abc" }] },
  });
  entry._resourceType = "xhr";
  entry.request._fromCache = false;
  const har = makeHar([entry]);
  har.log.pages = [{ id: "page_1", title: "t" }];
  const { har: out } = scrubHar(har, rules);
  assert.equal(out.log.entries[0]._resourceType, "xhr");
  assert.equal(out.log.entries[0].request._fromCache, false);
  assert.deepEqual(out.log.pages, [{ id: "page_1", title: "t" }]);
});

test("scrubbing a scrubbed HAR is a no-op in every mode", () => {
  const har = makeHar([
    makeEntry({
      request: {
        url: `https://u:pw@h.example.test/?access_token=${JWT}`,
        headers: [
          { name: "authorization", value: `Bearer ${JWT}` },
          { name: "cookie", value: "sid=abc" },
        ],
        queryString: [{ name: "access_token", value: JWT }],
        cookies: [{ name: "sid", value: "abc" }],
      },
      response: {
        content: { size: 30, mimeType: "application/json", text: '{"refresh_token":"rt-1"}' },
      },
    }),
  ]);
  for (const mode of ["mask", "hash", "remove"]) {
    const modeRules = buildRules({ mode, salt: "fixed" });
    const once = scrubHar(har, modeRules);
    const twice = scrubHar(once.har, modeRules);
    assert.deepEqual(twice.har, once.har, `${mode} mode must be idempotent`);
    assert.equal(twice.findings.length, 0, `${mode} second pass must find nothing`);
  }
});

test("auditHar reports the same findings a scrub performs", () => {
  const har = makeHar([
    makeEntry({ request: { headers: [{ name: "x-api-key", value: "k-123456" }] } }),
  ]);
  const audited = auditHar(har, rules);
  const scrubbed = scrubHar(har, rules).findings;
  assert.deepEqual(audited, scrubbed);
  assert.equal(JSON.stringify(har).includes("k-123456"), true, "audit does not mutate");
});

test("malformed entries (missing request/response) do not crash the engine", () => {
  const har = makeHar([{}, { request: null }, { response: { headers: "nope" } }]);
  const { findings } = scrubHar(har, rules);
  assert.equal(findings.length, 0);
});
