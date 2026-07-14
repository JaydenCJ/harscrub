/**
 * Body scrubbing: request payloads and response contents.
 *
 * Three strategies, chosen by mime type and shape:
 *   - JSON bodies are parsed and walked: values under sensitive keys are
 *     replaced at any depth, remaining string values are pattern-scanned,
 *     and the document is re-serialized *only if something changed* —
 *     an untouched body stays byte-identical, and a touched one keeps
 *     its indentation style so diffs stay readable.
 *   - `application/x-www-form-urlencoded` bodies are rewritten segment
 *     by segment, preserving separators and the encoding of untouched
 *     fields.
 *   - Everything else gets a token-pattern scan over the raw text.
 */

import { isPlaceholder, type Redactor } from "./placeholder.js";
import { matchesName } from "./rules.js";
import { scanText } from "./patterns.js";
import type { EffectiveRules } from "./types.js";

/** One redaction performed inside a body. */
export interface BodyFinding {
  rule: string;
  item: string;
  secret: string;
}

/** True for mime types that declare JSON (`application/json`, `+json`). */
export function isJsonMime(mimeType: string): boolean {
  const bare = mimeType.split(";")[0]?.trim().toLowerCase() ?? "";
  return bare === "application/json" || bare === "text/json" || bare.endsWith("+json");
}

/** True for classic HTML-form bodies. */
export function isFormMime(mimeType: string): boolean {
  const bare = mimeType.split(";")[0]?.trim().toLowerCase() ?? "";
  return bare === "application/x-www-form-urlencoded";
}

/** decodeURIComponent that never throws (malformed input stays raw). */
function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, "%20"));
  } catch {
    return text;
  }
}

/** Compact preview of a redacted non-string JSON value. */
function jsonSecret(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value) ?? "null";
}

/**
 * Walk a parsed JSON document, redacting in place. Returns true when
 * anything changed.
 */
function walkJson(
  node: unknown,
  rules: EffectiveRules,
  redactor: Redactor,
  findings: BodyFinding[],
): boolean {
  let changed = false;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const child = node[i];
      if (typeof child === "string") {
        const scanned = scanString(child, rules, redactor, findings);
        if (scanned !== null) {
          node[i] = scanned;
          changed = true;
        }
      } else {
        changed = walkJson(child, rules, redactor, findings) || changed;
      }
    }
    return changed;
  }
  if (typeof node !== "object" || node === null) return changed;

  const obj = node as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const sensitive =
      matchesName(rules.bodyKeys, key) && !matchesName(rules.bodyKeep, key);
    if (sensitive) {
      // Nothing to protect in a null or empty value, and re-redacting a
      // placeholder would break idempotency in hash mode.
      if (value === null) continue;
      if (typeof value === "string" && (value === "" || isPlaceholder(value))) continue;
      findings.push({ rule: "body-key", item: key, secret: jsonSecret(value) });
      if (redactor.mode === "remove") {
        delete obj[key];
      } else {
        // Non-string values (numbers, nested objects) become placeholder
        // strings: type fidelity loses to not leaking a nested secret.
        obj[key] = redactor.placeholder(jsonSecret(value));
      }
      changed = true;
    } else if (typeof value === "string") {
      const scanned = scanString(value, rules, redactor, findings);
      if (scanned !== null) {
        obj[key] = scanned;
        changed = true;
      }
    } else {
      changed = walkJson(value, rules, redactor, findings) || changed;
    }
  }
  return changed;
}

/** Pattern-scan one string; returns the new value or null if untouched. */
function scanString(
  value: string,
  rules: EffectiveRules,
  redactor: Redactor,
  findings: BodyFinding[],
): string | null {
  const scanned = scanText(value, rules.patterns, redactor);
  if (scanned.hits.length === 0) return null;
  for (const hit of scanned.hits) {
    findings.push({ rule: `pattern:${hit.pattern}`, item: hit.pattern, secret: hit.secret });
  }
  return scanned.text;
}

/** Detect the indentation of a pretty-printed JSON document. */
function detectIndent(text: string): number {
  const m = /^[{[]\r?\n([ \t]+)/.exec(text);
  if (!m || m[1] === undefined) return 0;
  return m[1].length;
}

/**
 * Scrub a JSON body. Returns null when the text is not parseable JSON
 * (the caller falls through to the free-text strategy).
 */
export function scrubJsonText(
  text: string,
  rules: EffectiveRules,
  redactor: Redactor,
): { text: string; findings: BodyFinding[] } | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  const findings: BodyFinding[] = [];
  const changed = walkJson(doc, rules, redactor, findings);
  if (!changed) return { text, findings };
  const indent = detectIndent(text);
  const out = indent > 0 ? JSON.stringify(doc, null, indent) : JSON.stringify(doc);
  return { text: out, findings };
}

/**
 * Scrub a `k=v&k2=v2` form body, preserving segment layout and the
 * encoding of untouched fields.
 */
export function scrubFormText(
  text: string,
  rules: EffectiveRules,
  redactor: Redactor,
): { text: string; findings: BodyFinding[] } {
  const findings: BodyFinding[] = [];
  const kept: string[] = [];
  for (const segment of text.split("&")) {
    const eq = segment.indexOf("=");
    if (eq < 0) {
      kept.push(segment);
      continue;
    }
    const rawName = segment.slice(0, eq);
    const rawValue = segment.slice(eq + 1);
    const name = safeDecode(rawName);
    const value = safeDecode(rawValue);
    if (
      matchesName(rules.bodyKeys, name) &&
      !matchesName(rules.bodyKeep, name) &&
      rawValue !== "" &&
      !isPlaceholder(value)
    ) {
      findings.push({ rule: "body-key", item: name, secret: value });
      if (redactor.mode === "remove") continue;
      kept.push(`${rawName}=${encodeURIComponent(redactor.placeholder(value))}`);
      continue;
    }
    const scanned = scanText(value, rules.patterns, redactor);
    if (scanned.hits.length > 0) {
      for (const hit of scanned.hits) {
        findings.push({ rule: `pattern:${hit.pattern}`, item: hit.pattern, secret: hit.secret });
      }
      kept.push(`${rawName}=${encodeURIComponent(scanned.text)}`);
      continue;
    }
    kept.push(segment);
  }
  return { text: kept.join("&"), findings };
}

/**
 * Scrub any body text given its mime type. JSON first (by mime or by
 * shape), then form encoding, then a raw pattern scan.
 */
export function scrubBodyText(
  text: string,
  mimeType: string,
  rules: EffectiveRules,
  redactor: Redactor,
): { text: string; findings: BodyFinding[] } {
  if (isJsonMime(mimeType) || text.trimStart().startsWith("{") || text.trimStart().startsWith("[")) {
    const asJson = scrubJsonText(text, rules, redactor);
    if (asJson !== null) return asJson;
  }
  if (isFormMime(mimeType)) {
    return scrubFormText(text, rules, redactor);
  }
  const scanned = scanText(text, rules.patterns, redactor);
  const findings: BodyFinding[] = scanned.hits.map((hit) => ({
    rule: `pattern:${hit.pattern}`,
    item: hit.pattern,
    secret: hit.secret,
  }));
  return { text: scanned.text, findings };
}
