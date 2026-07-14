/**
 * URL scrubbing without re-serialization.
 *
 * URLs are rewritten with string surgery, never round-tripped through a
 * URL parser: parsing and re-serializing would silently normalize case,
 * port defaults, percent-encoding and param order — and a scrubber's
 * whole job is to change *only* the secrets. Placeholders inserted into
 * a URL are percent-encoded so the result stays a strictly valid URL.
 */

import { isPlaceholder, type Redactor } from "./placeholder.js";
import { matchesName } from "./rules.js";
import { scanText } from "./patterns.js";
import type { EffectiveRules } from "./types.js";

/** One redaction performed inside a URL. */
export interface UrlFinding {
  rule: string;
  item: string;
  secret: string;
}

/** Matches `scheme://userinfo@` at the start of an absolute URL. */
const USERINFO_RE = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#@]+)@/i;

/** decodeURIComponent that never throws (malformed input stays raw). */
function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, "%20"));
  } catch {
    return text;
  }
}

/** A redactor whose placeholders are safe to embed in a URL. */
function urlRedactor(redactor: Redactor): Redactor {
  return {
    mode: redactor.mode,
    placeholder: (value: string) => encodeURIComponent(redactor.placeholder(value)),
  };
}

/**
 * Scrub one query segment (`name=value`). Returns the rewritten
 * segment, or null when `remove` mode drops it.
 */
function scrubSegment(
  segment: string,
  rules: EffectiveRules,
  redactor: Redactor,
  findings: UrlFinding[],
): string | null {
  const eq = segment.indexOf("=");
  if (eq < 0) return segment; // bare flag, no value to leak
  const rawName = segment.slice(0, eq);
  const rawValue = segment.slice(eq + 1);
  const name = safeDecode(rawName);
  const value = safeDecode(rawValue);

  if (
    matchesName(rules.queryParams, name) &&
    !matchesName(rules.queryKeep, name) &&
    rawValue !== "" &&
    !isPlaceholder(value)
  ) {
    findings.push({ rule: "query-param", item: name, secret: value });
    if (redactor.mode === "remove") return null;
    return `${rawName}=${encodeURIComponent(redactor.placeholder(value))}`;
  }

  // Not a sensitive name: the value may still be a recognizable token
  // (a JWT in a `next=` redirect, for example).
  const scanned = scanText(value, rules.patterns, redactor);
  if (scanned.hits.length > 0) {
    for (const hit of scanned.hits) {
      findings.push({ rule: `pattern:${hit.pattern}`, item: hit.pattern, secret: hit.secret });
    }
    return `${rawName}=${encodeURIComponent(scanned.text)}`;
  }
  return segment;
}

/**
 * Scrub credentials out of a URL: userinfo passwords, sensitive query
 * parameters (by name), and recognizable tokens anywhere in the path or
 * query. Everything that is not a secret is preserved byte-for-byte.
 */
export function scrubUrl(
  url: string,
  rules: EffectiveRules,
  redactor: Redactor,
): { url: string; findings: UrlFinding[] } {
  const findings: UrlFinding[] = [];
  let out = url;

  // 1. userinfo — `https://user:pass@host/` leaks a live password.
  const userinfo = USERINFO_RE.exec(out);
  if (userinfo) {
    const [whole, scheme, info] = userinfo as unknown as [string, string, string];
    const colon = info.indexOf(":");
    if (colon >= 0) {
      const user = info.slice(0, colon);
      const pass = safeDecode(info.slice(colon + 1));
      if (pass !== "" && !isPlaceholder(pass)) {
        findings.push({ rule: "url-credentials", item: user, secret: pass });
        if (redactor.mode === "remove") {
          out = scheme + out.slice(whole.length);
        } else {
          const masked = `${scheme}${user}:${encodeURIComponent(redactor.placeholder(pass))}@`;
          out = masked + out.slice(whole.length);
        }
      }
    }
  }

  // 2. Split off the fragment, then the query.
  const hashAt = out.indexOf("#");
  const fragment = hashAt >= 0 ? out.slice(hashAt) : "";
  let base = hashAt >= 0 ? out.slice(0, hashAt) : out;

  const qAt = base.indexOf("?");
  let head = qAt >= 0 ? base.slice(0, qAt) : base;
  const query = qAt >= 0 ? base.slice(qAt + 1) : null;

  // 3. Tokens embedded in the path (e.g. /verify/eyJ…).
  const pathScan = scanText(head, rules.patterns, urlRedactor(redactor));
  if (pathScan.hits.length > 0) {
    for (const hit of pathScan.hits) {
      findings.push({ rule: `pattern:${hit.pattern}`, item: hit.pattern, secret: hit.secret });
    }
    head = pathScan.text;
  }

  // 4. Query parameters, one segment at a time; `&` layout is preserved.
  if (query !== null) {
    const kept: string[] = [];
    for (const segment of query.split("&")) {
      const scrubbed = scrubSegment(segment, rules, redactor, findings);
      if (scrubbed !== null) kept.push(scrubbed);
    }
    base = kept.length > 0 ? `${head}?${kept.join("&")}` : head;
  } else {
    base = head;
  }

  return { url: base + fragment, findings };
}
