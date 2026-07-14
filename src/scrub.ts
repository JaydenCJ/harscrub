/**
 * The scrub engine: walks a HAR document and rewrites every place a
 * credential can hide, keeping the file valid HAR 1.2 throughout.
 *
 * HAR stores the same data in several mirrors — the raw `Cookie` header
 * *and* the parsed `request.cookies` array; the URL query string *and*
 * the parsed `request.queryString` array; `postData.text` *and*
 * `postData.params`. A scrubber that cleans one mirror and forgets the
 * other has leaked. Every mirror is handled here, and `hash` mode
 * derives placeholders from the decoded value so mirrors of the same
 * secret carry the same tag.
 */

import { isPlaceholder, makeRedactor, preview, type Redactor } from "./placeholder.js";
import { matchesName } from "./rules.js";
import { scanText } from "./patterns.js";
import { scrubUrl } from "./urlscrub.js";
import { scrubBodyText, type BodyFinding } from "./bodyscrub.js";
import type {
  EffectiveRules,
  Finding,
  FindingLocation,
  Har,
  HarContent,
  HarCookie,
  HarEntry,
  HarPostData,
  NameValue,
  ScrubResult,
} from "./types.js";

/** Auth schemes whose name is kept in front of the placeholder. */
const AUTH_SCHEMES = new Set([
  "basic",
  "bearer",
  "digest",
  "token",
  "negotiate",
  "ntlm",
  "hoba",
  "mutual",
  "vapid",
  "aws4-hmac-sha256",
]);

/** Header names whose values are URLs worth query-scrubbing. */
const URL_HEADERS = new Set(["location", "referer", "content-location"]);

/** Collects findings for one entry; keeps call sites terse. */
class Recorder {
  findings: Finding[] = [];
  constructor(
    private entry: number,
    private mode: Redactor["mode"],
  ) {}

  add(location: FindingLocation, rule: string, item: string, secret: string): void {
    this.findings.push({
      entry: this.entry,
      location,
      rule,
      item,
      action: this.mode,
      preview: preview(secret),
    });
  }
}

/** Redact a header value, keeping a recognizable auth scheme prefix. */
function redactHeaderValue(value: string, redactor: Redactor): string {
  const m = /^([A-Za-z0-9-]+)[ \t]+(\S[\s\S]*)$/.exec(value);
  if (m && m[1] !== undefined && m[2] !== undefined && AUTH_SCHEMES.has(m[1].toLowerCase())) {
    return `${m[1]} ${redactor.placeholder(m[2])}`;
  }
  return redactor.placeholder(value);
}

/** The credential part a scheme-prefixed header actually leaks. */
function headerSecret(value: string): string {
  const m = /^([A-Za-z0-9-]+)[ \t]+(\S[\s\S]*)$/.exec(value);
  if (m && m[1] !== undefined && m[2] !== undefined && AUTH_SCHEMES.has(m[1].toLowerCase())) {
    return m[2];
  }
  return value;
}

/**
 * Scrub a raw `Cookie` request-header value (`a=1; b=2`), preserving
 * separator spacing. Returns null when `remove` mode leaves no cookies.
 */
export function scrubCookieHeaderValue(
  value: string,
  rules: EffectiveRules,
  redactor: Redactor,
  onCookie: (name: string, secret: string) => void,
): string | null {
  const kept: string[] = [];
  for (const segment of value.split(";")) {
    const m = /^(\s*)([^=]+?)(\s*=\s*)([\s\S]*)$/.exec(segment);
    if (!m) {
      kept.push(segment);
      continue;
    }
    const [, lead = "", name = "", eq = "=", val = ""] = m;
    if (matchesName(rules.cookieKeep, name) || val === "" || isPlaceholder(val)) {
      kept.push(segment);
      continue;
    }
    onCookie(name, val);
    if (redactor.mode === "remove") continue;
    kept.push(`${lead}${name}${eq}${redactor.placeholder(val)}`);
  }
  if (kept.length === 0) return null;
  return kept.join(";").replace(/^\s+/, "");
}

/**
 * Scrub a `Set-Cookie` response-header value: only the leading
 * `name=value` pair is a secret; attributes (Path, Expires, HttpOnly…)
 * are metadata worth keeping in a bug report.
 */
function scrubSetCookieValue(
  value: string,
  rules: EffectiveRules,
  redactor: Redactor,
  onCookie: (name: string, secret: string) => void,
): string {
  const semi = value.indexOf(";");
  const pair = semi >= 0 ? value.slice(0, semi) : value;
  const attrs = semi >= 0 ? value.slice(semi) : "";
  const eq = pair.indexOf("=");
  if (eq < 0) return value;
  const name = pair.slice(0, eq).trim();
  const val = pair.slice(eq + 1);
  if (matchesName(rules.cookieKeep, name) || val === "" || isPlaceholder(val)) return value;
  onCookie(name, val);
  return `${pair.slice(0, eq + 1)}${redactor.placeholder(val)}${attrs}`;
}

/** Scrub one headers array in place. Returns true when changed. */
function scrubHeaders(
  headers: NameValue[],
  side: "request" | "response",
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): boolean {
  const location: FindingLocation = side === "request" ? "request.headers" : "response.headers";
  let changed = false;
  for (let i = headers.length - 1; i >= 0; i--) {
    const header = headers[i];
    if (!header || typeof header.name !== "string" || typeof header.value !== "string") continue;
    const lower = header.name.toLowerCase();

    if (lower === "cookie") {
      const out = scrubCookieHeaderValue(header.value, rules, redactor, (name, secret) =>
        rec.add(location, "cookie", name, secret),
      );
      if (out === null) {
        headers.splice(i, 1);
        changed = true;
      } else if (out !== header.value) {
        header.value = out;
        changed = true;
      }
      continue;
    }

    if (lower === "set-cookie") {
      // Multi-line Set-Cookie values (Chrome folds them) are handled
      // line by line.
      const out = header.value
        .split("\n")
        .map((line) =>
          scrubSetCookieValue(line, rules, redactor, (name, secret) =>
            rec.add(location, "cookie", name, secret),
          ),
        )
        .join("\n");
      if (out !== header.value) {
        header.value = out;
        changed = true;
      }
      continue;
    }

    if (matchesName(rules.headers, header.name) && !matchesName(rules.headerKeep, header.name)) {
      // The idempotency check must look at the credential part: a prior
      // run may have left `Bearer [REDACTED:…]`, which must not be
      // re-hashed into a fresh tag.
      if (header.value === "" || isPlaceholder(headerSecret(header.value))) continue;
      rec.add(location, "header", lower, headerSecret(header.value));
      if (redactor.mode === "remove") {
        headers.splice(i, 1);
      } else {
        header.value = redactHeaderValue(header.value, redactor);
      }
      changed = true;
      continue;
    }

    if (URL_HEADERS.has(lower)) {
      const scrubbed = scrubUrl(header.value, rules, redactor);
      if (scrubbed.url !== header.value) {
        for (const f of scrubbed.findings) rec.add(location, f.rule, f.item, f.secret);
        header.value = scrubbed.url;
        changed = true;
      }
      continue;
    }

    // Any other header may still carry a recognizable token.
    const scanned = scanText(header.value, rules.patterns, redactor);
    if (scanned.hits.length > 0) {
      for (const hit of scanned.hits) {
        rec.add(location, `pattern:${hit.pattern}`, hit.pattern, hit.secret);
      }
      header.value = scanned.text;
      changed = true;
    }
  }
  return changed;
}

/** Scrub a parsed cookies array (request or response) in place. */
function scrubCookiesArray(
  cookies: HarCookie[],
  location: FindingLocation,
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): void {
  for (let i = cookies.length - 1; i >= 0; i--) {
    const cookie = cookies[i];
    if (!cookie || typeof cookie.name !== "string" || typeof cookie.value !== "string") continue;
    if (matchesName(rules.cookieKeep, cookie.name)) continue;
    if (cookie.value === "" || isPlaceholder(cookie.value)) continue;
    rec.add(location, "cookie", cookie.name, cookie.value);
    if (redactor.mode === "remove") {
      cookies.splice(i, 1);
    } else {
      cookie.value = redactor.placeholder(cookie.value);
    }
  }
}

/** Scrub the parsed queryString mirror of the URL. */
function scrubQueryArray(
  params: NameValue[],
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): void {
  for (let i = params.length - 1; i >= 0; i--) {
    const param = params[i];
    if (!param || typeof param.name !== "string" || typeof param.value !== "string") continue;
    if (
      matchesName(rules.queryParams, param.name) &&
      !matchesName(rules.queryKeep, param.name)
    ) {
      if (param.value === "" || isPlaceholder(param.value)) continue;
      rec.add("request.queryString", "query-param", param.name, param.value);
      if (redactor.mode === "remove") {
        params.splice(i, 1);
      } else {
        param.value = redactor.placeholder(param.value);
      }
      continue;
    }
    const scanned = scanText(param.value, rules.patterns, redactor);
    if (scanned.hits.length > 0) {
      for (const hit of scanned.hits) {
        rec.add("request.queryString", `pattern:${hit.pattern}`, hit.pattern, hit.secret);
      }
      param.value = scanned.text;
    }
  }
}

/** Scrub postData: the text body and, for forms, the params mirror. */
function scrubPostData(
  postData: HarPostData,
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): boolean {
  let changed = false;
  const mime = typeof postData.mimeType === "string" ? postData.mimeType : "";

  if (Array.isArray(postData.params)) {
    for (let i = postData.params.length - 1; i >= 0; i--) {
      const param = postData.params[i];
      if (!param || typeof param.name !== "string" || typeof param.value !== "string") continue;
      if (
        matchesName(rules.bodyKeys, param.name) &&
        !matchesName(rules.bodyKeep, param.name)
      ) {
        if (param.value === "" || isPlaceholder(param.value)) continue;
        rec.add("request.postData.params", "body-key", param.name, param.value);
        if (redactor.mode === "remove") {
          postData.params.splice(i, 1);
        } else {
          param.value = redactor.placeholder(param.value);
        }
        changed = true;
        continue;
      }
      const scanned = scanText(param.value, rules.patterns, redactor);
      if (scanned.hits.length > 0) {
        for (const hit of scanned.hits) {
          rec.add("request.postData.params", `pattern:${hit.pattern}`, hit.pattern, hit.secret);
        }
        param.value = scanned.text;
        changed = true;
      }
    }
  }

  if (typeof postData.text === "string" && postData.text !== "") {
    const result = scrubBodyText(postData.text, mime, rules, redactor);
    recordBodyFindings(result.findings, "request.postData", rec);
    if (result.text !== postData.text) {
      postData.text = result.text;
      changed = true;
    }
  }
  return changed;
}

/** Forward body-scrubber findings into the entry recorder. */
function recordBodyFindings(
  findings: BodyFinding[],
  location: FindingLocation,
  rec: Recorder,
): void {
  for (const f of findings) rec.add(location, f.rule, f.item, f.secret);
}

/** True when a decoded buffer looks like text we can safely rewrite. */
function decodesCleanly(original: string, decoded: string): boolean {
  if (decoded.includes("�")) return false;
  // Round-trip: if re-encoding does not reproduce the original bytes,
  // the body was not base64 text and must be left alone.
  return Buffer.from(decoded, "utf8").toString("base64") === original.replace(/\s+/g, "");
}

/** Scrub response content, including base64-encoded text bodies. */
function scrubContent(
  content: HarContent,
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): void {
  if (typeof content.text !== "string" || content.text === "") return;

  if (rules.dropContent) {
    rec.add("response.content", "drop-content", content.mimeType ?? "body", content.text);
    delete content.text;
    delete content.encoding;
    content.comment = "body removed by harscrub --drop-content";
    return;
  }

  const mime = typeof content.mimeType === "string" ? content.mimeType : "";

  if (content.encoding === "base64") {
    const decoded = Buffer.from(content.text, "base64").toString("utf8");
    if (!decodesCleanly(content.text, decoded)) return; // binary: leave alone
    const result = scrubBodyText(decoded, mime, rules, redactor);
    recordBodyFindings(result.findings, "response.content", rec);
    if (result.text !== decoded) {
      content.text = Buffer.from(result.text, "utf8").toString("base64");
      if (typeof content.size === "number" && content.size >= 0) {
        content.size = Buffer.byteLength(result.text);
      }
    }
    return;
  }

  const result = scrubBodyText(content.text, mime, rules, redactor);
  recordBodyFindings(result.findings, "response.content", rec);
  if (result.text !== content.text) {
    content.text = result.text;
    if (typeof content.size === "number" && content.size >= 0) {
      content.size = Buffer.byteLength(result.text);
    }
  }
}

/** Scrub one entry in place, appending findings to the recorder. */
function scrubEntry(
  entry: HarEntry,
  rules: EffectiveRules,
  redactor: Redactor,
  rec: Recorder,
): void {
  const request = entry.request;
  if (request && typeof request === "object") {
    if (typeof request.url === "string") {
      const scrubbed = scrubUrl(request.url, rules, redactor);
      if (scrubbed.url !== request.url) {
        for (const f of scrubbed.findings) rec.add("request.url", f.rule, f.item, f.secret);
        request.url = scrubbed.url;
      }
    }
    if (Array.isArray(request.queryString)) {
      scrubQueryArray(request.queryString, rules, redactor, rec);
    }
    let headersChanged = false;
    if (Array.isArray(request.headers)) {
      headersChanged = scrubHeaders(request.headers, "request", rules, redactor, rec);
    }
    if (Array.isArray(request.cookies)) {
      scrubCookiesArray(request.cookies, "request.cookies", rules, redactor, rec);
    }
    let bodyChanged = false;
    if (request.postData && typeof request.postData === "object") {
      bodyChanged = scrubPostData(request.postData, rules, redactor, rec);
    }
    // Sizes describe the original wire bytes; once rewritten they are
    // recomputed where cheap and marked unknown (-1) where not.
    if (headersChanged && typeof request.headersSize === "number" && request.headersSize >= 0) {
      request.headersSize = -1;
    }
    if (
      bodyChanged &&
      typeof request.bodySize === "number" &&
      request.bodySize >= 0 &&
      typeof request.postData?.text === "string"
    ) {
      request.bodySize = Buffer.byteLength(request.postData.text);
    }
  }

  const response = entry.response;
  if (response && typeof response === "object") {
    let headersChanged = false;
    if (Array.isArray(response.headers)) {
      headersChanged = scrubHeaders(response.headers, "response", rules, redactor, rec);
    }
    if (Array.isArray(response.cookies)) {
      scrubCookiesArray(response.cookies, "response.cookies", rules, redactor, rec);
    }
    if (typeof response.redirectURL === "string" && response.redirectURL !== "") {
      const scrubbed = scrubUrl(response.redirectURL, rules, redactor);
      if (scrubbed.url !== response.redirectURL) {
        for (const f of scrubbed.findings) {
          rec.add("response.redirectURL", f.rule, f.item, f.secret);
        }
        response.redirectURL = scrubbed.url;
      }
    }
    if (response.content && typeof response.content === "object") {
      scrubContent(response.content, rules, redactor, rec);
    }
    if (headersChanged && typeof response.headersSize === "number" && response.headersSize >= 0) {
      response.headersSize = -1;
    }
  }
}

/**
 * Scrub a HAR document. The input value is never mutated; the returned
 * `har` is a deep copy with secrets replaced, and `findings` lists one
 * record per redacted occurrence (mirrors count separately — each is a
 * real place the secret sat in the file).
 */
export function scrubHar(har: Har, rules: EffectiveRules): ScrubResult {
  const copy = JSON.parse(JSON.stringify(har)) as Har;
  const redactor = makeRedactor(rules.mode, rules.salt);
  const findings: Finding[] = [];
  const entries = copy.log?.entries;
  if (Array.isArray(entries)) {
    entries.forEach((entry, index) => {
      if (!entry || typeof entry !== "object") return;
      const rec = new Recorder(index, redactor.mode);
      scrubEntry(entry, rules, redactor, rec);
      findings.push(...rec.findings);
    });
  }
  return { har: copy, findings };
}

/**
 * Audit a HAR document: report what a scrub *would* redact without
 * producing output. Identical rule evaluation by construction — it runs
 * the same engine on a throwaway copy.
 */
export function auditHar(har: Har, rules: EffectiveRules): Finding[] {
  return scrubHar(har, rules).findings;
}
