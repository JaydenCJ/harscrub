// Reporting: aggregation, the audit table, and the JSON document —
// all pure functions of the findings list.
import test from "node:test";
import assert from "node:assert/strict";

import {
  formatAudit,
  formatOneLine,
  formatSummaryTable,
  summarize,
  toJsonReport,
} from "../dist/report.js";

const finding = (entry, rule, item = "x") => ({
  entry,
  location: "request.headers",
  rule,
  item,
  action: "mask",
  preview: "abc…",
});

test("summarize counts totals, distinct entries and per-rule occurrences", () => {
  const s = summarize([finding(0, "header"), finding(0, "cookie"), finding(2, "header")]);
  assert.equal(s.total, 3);
  assert.equal(s.entries, 2);
  assert.deepEqual(s.byRule, [
    { rule: "header", count: 2 },
    { rule: "cookie", count: 1 },
  ]);
  // Count ties break by rule name, keeping output stable across runs.
  const ties = summarize([finding(0, "z-rule"), finding(0, "a-rule")]);
  assert.deepEqual(ties.byRule.map((r) => r.rule), ["a-rule", "z-rule"]);
});

test("formatAudit renders a header row, aligned columns and a summary line", () => {
  const out = formatAudit([finding(0, "header", "authorization"), finding(3, "cookie", "sid")]);
  const lines = out.trimEnd().split("\n");
  assert.match(lines[0], /^ENTRY\s+LOCATION\s+RULE\s+ITEM\s+PREVIEW$/);
  assert.match(lines[1], /^#0\s+request\.headers\s+header\s+authorization\s+abc…$/);
  assert.equal(lines.at(-1), "2 findings in 2 entries");
});

test("formatAudit and formatSummaryTable handle the empty case", () => {
  assert.equal(formatAudit([]), "no redactable values found\n");
  assert.equal(formatSummaryTable([]), "nothing to redact\n");
});

test("formatOneLine uses singular/plural forms correctly", () => {
  assert.equal(
    formatOneLine([finding(0, "header")], "mask"),
    "harscrub: 1 value redacted across 1 entry (mode: mask)",
  );
  assert.match(formatOneLine([finding(0, "a"), finding(1, "b")], "hash"), /2 values .* 2 entries/);
});

test("toJsonReport is valid JSON with findings and an aggregated summary", () => {
  const doc = JSON.parse(toJsonReport([finding(0, "header"), finding(0, "header")]));
  assert.equal(doc.findings.length, 2);
  assert.equal(doc.summary.total, 2);
  assert.equal(doc.summary.entries, 1);
  assert.deepEqual(doc.summary.byRule, { header: 2 });
});
