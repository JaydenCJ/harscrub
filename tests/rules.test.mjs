// Rule model: name matching (literals + globs), rules-file validation
// (typos must be fatal), and the defaults→file→flags merge precedence.
import test from "node:test";
import assert from "node:assert/strict";

import {
  buildRules,
  compileNames,
  matchesName,
  validateRuleFile,
  DEFAULT_HEADERS,
  DEFAULT_QUERY_PARAMS,
  DEFAULT_BODY_KEYS,
} from "../dist/rules.js";

test("literal name matching is case-insensitive", () => {
  const m = compileNames(["Authorization", "x-api-key"]);
  assert.ok(matchesName(m, "authorization"));
  assert.ok(matchesName(m, "AUTHORIZATION"));
  assert.ok(matchesName(m, "X-Api-Key"));
  assert.ok(!matchesName(m, "authorization2"));
});

test("glob names match by * wildcard, anchored at both ends", () => {
  const m = compileNames(["x-internal-*", "*-signature"]);
  assert.ok(matchesName(m, "x-internal-auth"));
  assert.ok(matchesName(m, "X-Internal-Session-Id"));
  assert.ok(matchesName(m, "hub-signature"));
  assert.ok(!matchesName(m, "not-x-internal-auth"), "prefix glob is anchored");
  assert.ok(!matchesName(m, "x-signature-v2"), "suffix glob is anchored");
  // Regex metacharacters in the literal parts are escaped.
  const dotted = compileNames(["x.y*"]);
  assert.ok(matchesName(dotted, "x.y-anything"));
  assert.ok(!matchesName(dotted, "xzy-anything"), "the dot must be literal");
});

test("buildRules defaults: mask mode, classic carriers, all built-in patterns", () => {
  const rules = buildRules();
  assert.equal(rules.mode, "mask");
  assert.equal(rules.salt, "");
  assert.equal(rules.dropContent, false);
  assert.ok(rules.patterns.length >= 10);
  assert.ok(matchesName(rules.headers, "authorization"));
  assert.ok(DEFAULT_HEADERS.includes("x-api-key"));
  assert.ok(DEFAULT_QUERY_PARAMS.includes("access_token"));
  assert.ok(DEFAULT_BODY_KEYS.includes("password"));
  assert.ok(DEFAULT_BODY_KEYS.includes("client_secret"));
});

test("rules file adds names without losing the defaults", () => {
  const rules = buildRules({ headers: { add: ["x-acme-token"] } });
  assert.ok(matchesName(rules.headers, "x-acme-token"));
  assert.ok(matchesName(rules.headers, "authorization"), "defaults survive an add");
});

test("keep lists punch holes; CLI overrides beat the file", () => {
  const rules = buildRules(
    { mode: "hash", queryParams: { keep: ["code"] } },
    { mode: "remove", salt: "s" },
  );
  assert.equal(rules.mode, "remove", "flag wins over file");
  assert.equal(rules.salt, "s");
  assert.ok(matchesName(rules.queryKeep, "code"));
});

test("patterns: disable removes a built-in, customs are compiled in", () => {
  const rules = buildRules({
    patterns: { disable: ["sk-api-key"], custom: [{ name: "acme", regex: "acme_[0-9]{4}" }] },
  });
  assert.ok(!rules.patterns.some((p) => p.name === "sk-api-key"));
  const custom = rules.patterns.find((p) => p.name === "acme");
  assert.ok(custom);
  assert.equal(custom.builtin, false);
  assert.throws(() => buildRules({ patterns: { disable: ["no-such"] } }), /unknown pattern/);
});

test("validateRuleFile rejects unknown top-level and nested keys", () => {
  // A typo like "header" must not silently leave credentials in place.
  assert.throws(() => validateRuleFile({ header: {} }), /unknown key "\$\.header"/);
  assert.throws(() => validateRuleFile({ headers: { include: [] } }), /unknown key "headers\.include"/);
  assert.throws(() => validateRuleFile({ cookies: { add: [] } }), /unknown key "cookies\.add"/);
});

test("validateRuleFile rejects wrong types with a path in the message", () => {
  assert.throws(() => validateRuleFile("not an object"), /top level/);
  assert.throws(() => validateRuleFile({ mode: "shred" }), /"mode" must be one of/);
  assert.throws(() => validateRuleFile({ salt: 5 }), /"salt" must be a string/);
  assert.throws(() => validateRuleFile({ dropContent: "yes" }), /"dropContent" must be a boolean/);
  assert.throws(() => validateRuleFile({ headers: { add: [1] } }), /"headers\.add" must be an array of strings/);
});

test("validateRuleFile checks custom pattern entries field by field", () => {
  assert.throws(
    () => validateRuleFile({ patterns: { custom: [{ regex: "x" }] } }),
    /custom\[0\]\.name/,
  );
  assert.throws(
    () => validateRuleFile({ patterns: { custom: [{ name: "a", regex: "" }] } }),
    /custom\[0\]\.regex/,
  );
  assert.throws(
    () => validateRuleFile({ patterns: { custom: [{ name: "a", regex: "x", extra: 1 }] } }),
    /unknown key "patterns\.custom\[0\]\.extra"/,
  );
  // A fully valid file passes through unchanged.
  const ok = validateRuleFile({ patterns: { custom: [{ name: "a", regex: "x" }] } });
  assert.equal(ok.patterns.custom[0].name, "a");
});
