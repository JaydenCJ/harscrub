// Body scrubbing: JSON key redaction at depth, layout preservation,
// form-encoded bodies, and the raw-text fallback.
import test from "node:test";
import assert from "node:assert/strict";

import {
  isFormMime,
  isJsonMime,
  scrubBodyText,
  scrubFormText,
  scrubJsonText,
} from "../dist/bodyscrub.js";
import { buildRules } from "../dist/rules.js";
import { makeRedactor } from "../dist/placeholder.js";
import { JWT } from "./helpers.mjs";

const rules = buildRules();
const mask = makeRedactor("mask", "");

test("json: sensitive keys are redacted at any nesting depth", () => {
  const body = JSON.stringify({
    user: "demo",
    auth: { password: "hunter2", nested: { refresh_token: "rt-1" } },
    items: [{ api_key: "k-1" }],
  });
  const { text, findings } = scrubJsonText(body, rules, mask);
  const doc = JSON.parse(text);
  assert.equal(doc.user, "demo");
  assert.equal(doc.auth.password, "[REDACTED]");
  assert.equal(doc.auth.nested.refresh_token, "[REDACTED]");
  assert.equal(doc.items[0].api_key, "[REDACTED]");
  assert.deepEqual(findings.map((f) => f.item).sort(), ["api_key", "password", "refresh_token"]);
});

test("json: non-string secrets become placeholder strings; remove mode deletes keys", () => {
  const body = JSON.stringify({ pin: 1234, secret: { k: "v" } });
  const { text } = scrubJsonText(body, rules, mask);
  const doc = JSON.parse(text);
  assert.equal(doc.pin, "[REDACTED]");
  assert.equal(doc.secret, "[REDACTED]");
  const remover = makeRedactor("remove", "");
  const removed = scrubJsonText(JSON.stringify({ a: 1, password: "x" }), rules, remover);
  assert.deepEqual(JSON.parse(removed.text), { a: 1 });
});

test("json: null and empty sensitive values are not findings", () => {
  const body = JSON.stringify({ password: null, token: "" });
  const { text, findings } = scrubJsonText(body, rules, mask);
  assert.equal(findings.length, 0);
  assert.equal(text, body, "untouched body is byte-identical");
});

test("json: tokens inside benign string values are pattern-scanned", () => {
  const body = JSON.stringify({ note: `use ${JWT} to log in`, list: [`key AKIAIOSFODNN7EXAMPLE`] });
  const { text, findings } = scrubJsonText(body, rules, mask);
  assert.ok(!text.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(!text.includes(JWT.slice(0, 20)));
  assert.deepEqual(findings.map((f) => f.rule).sort(), ["pattern:aws-access-key-id", "pattern:jwt"]);
});

test("json: pretty documents keep their indentation, compact stay compact", () => {
  const pretty = JSON.stringify({ token: "abc", ok: true }, null, 4);
  const prettyOut = scrubJsonText(pretty, rules, mask).text;
  assert.ok(prettyOut.includes('\n    "token": "[REDACTED]"'), prettyOut);
  const compact = JSON.stringify({ token: "abc", ok: true });
  const compactOut = scrubJsonText(compact, rules, mask).text;
  assert.equal(compactOut, '{"token":"[REDACTED]","ok":true}');
});

test("json: unparseable text returns null so the caller can fall back", () => {
  assert.equal(scrubJsonText("{not json", rules, mask), null);
  assert.equal(scrubJsonText("plain text", rules, mask), null);
});

test("form: sensitive fields are redacted, layout and encoding preserved", () => {
  const body = "grant_type=password&username=demo&password=hunter2&client_secret=s3cr3t";
  const { text, findings } = scrubFormText(body, rules, mask);
  assert.equal(
    text,
    "grant_type=password&username=demo&password=%5BREDACTED%5D&client_secret=%5BREDACTED%5D",
  );
  assert.deepEqual(findings.map((f) => f.item), ["password", "client_secret"]);
  // Name-based rules key on the NAME; grant_type=password is protocol
  // vocabulary, not a credential.
  const benign = scrubFormText("grant_type=password", rules, mask);
  assert.equal(benign.text, "grant_type=password");
  assert.equal(benign.findings.length, 0);
});

test("form: remove mode drops the field, other segments keep positions", () => {
  const remover = makeRedactor("remove", "");
  const { text } = scrubFormText("a=1&password=x&b=2", rules, remover);
  assert.equal(text, "a=1&b=2");
});

test("scrubBodyText picks JSON by mime or shape, else falls back to a raw scan", () => {
  // Mime detection is charset- and suffix-tolerant.
  assert.ok(isJsonMime("application/json"));
  assert.ok(isJsonMime("application/json; charset=utf-8"));
  assert.ok(isJsonMime("application/problem+json"));
  assert.ok(!isJsonMime("text/html"));
  assert.ok(isFormMime("application/x-www-form-urlencoded; charset=UTF-8"));
  assert.ok(!isFormMime("multipart/form-data"));
  const byMime = scrubBodyText('{"token":"t-1"}', "application/vnd.api+json", rules, mask);
  assert.equal(JSON.parse(byMime.text).token, "[REDACTED]");
  const byShape = scrubBodyText('{"token":"t-2"}', "text/plain", rules, mask);
  assert.equal(JSON.parse(byShape.text).token, "[REDACTED]");
  const raw = scrubBodyText(`<html>token ${JWT}</html>`, "text/html", rules, mask);
  assert.equal(raw.text, "<html>token [REDACTED]</html>");
  assert.equal(raw.findings[0].rule, "pattern:jwt");
});

test("bodyKeys keep/add configuration reaches JSON and form bodies", () => {
  const custom = buildRules({ bodyKeys: { add: ["mfa"], keep: ["token"] } });
  const { text } = scrubJsonText(JSON.stringify({ token: "keepme", mfa: "123456" }), custom, mask);
  const doc = JSON.parse(text);
  assert.equal(doc.token, "keepme");
  assert.equal(doc.mfa, "[REDACTED]");
});
