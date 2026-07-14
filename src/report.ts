/**
 * Reporting: turning the engine's findings into the audit listing, the
 * per-rule summary table, and a machine-readable JSON document.
 * Everything here is pure string building — deterministic given the
 * findings, no clocks, no environment.
 */

import type { Finding } from "./types.js";

/** Aggregate view of a findings list. */
export interface Summary {
  total: number;
  /** Distinct entry indexes touched. */
  entries: number;
  /** rule → occurrence count, insertion-ordered by first appearance. */
  byRule: Array<{ rule: string; count: number }>;
}

/** Build the aggregate summary. */
export function summarize(findings: Finding[]): Summary {
  const entries = new Set<number>();
  const byRule = new Map<string, number>();
  for (const f of findings) {
    entries.add(f.entry);
    byRule.set(f.rule, (byRule.get(f.rule) ?? 0) + 1);
  }
  const rows = [...byRule.entries()]
    .map(([rule, count]) => ({ rule, count }))
    .sort((a, b) => b.count - a.count || (a.rule < b.rule ? -1 : 1));
  return { total: findings.length, entries: entries.size, byRule: rows };
}

/** Left-pad-free column layout: pad every cell to its column's width. */
function layout(rows: string[][]): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, cell.length);
    });
  }
  return rows.map((row) =>
    row
      .map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i] ?? 0)))
      .join("  ")
      .trimEnd(),
  );
}

/** The one-finding-per-line audit listing. */
export function formatAudit(findings: Finding[]): string {
  if (findings.length === 0) return "no redactable values found\n";
  const rows: string[][] = [["ENTRY", "LOCATION", "RULE", "ITEM", "PREVIEW"]];
  for (const f of findings) {
    rows.push([`#${f.entry}`, f.location, f.rule, f.item, f.preview]);
  }
  const summary = summarize(findings);
  const noun = summary.total === 1 ? "finding" : "findings";
  const entryNoun = summary.entries === 1 ? "entry" : "entries";
  return `${layout(rows).join("\n")}\n\n${summary.total} ${noun} in ${summary.entries} ${entryNoun}\n`;
}

/** The per-rule table printed by `scrub --report`. */
export function formatSummaryTable(findings: Finding[]): string {
  const summary = summarize(findings);
  if (summary.total === 0) return "nothing to redact\n";
  const rows: string[][] = [["RULE", "COUNT"]];
  for (const row of summary.byRule) {
    rows.push([row.rule, String(row.count)]);
  }
  return `${layout(rows).join("\n")}\n`;
}

/** One-line summary for stderr after a scrub. */
export function formatOneLine(findings: Finding[], mode: string): string {
  const summary = summarize(findings);
  const noun = summary.total === 1 ? "value" : "values";
  const entryNoun = summary.entries === 1 ? "entry" : "entries";
  return `harscrub: ${summary.total} ${noun} redacted across ${summary.entries} ${entryNoun} (mode: ${mode})`;
}

/** Machine-readable report for `--json`. */
export function toJsonReport(findings: Finding[]): string {
  const summary = summarize(findings);
  return `${JSON.stringify(
    {
      findings,
      summary: {
        total: summary.total,
        entries: summary.entries,
        byRule: Object.fromEntries(summary.byRule.map((r) => [r.rule, r.count])),
      },
    },
    null,
    2,
  )}\n`;
}
