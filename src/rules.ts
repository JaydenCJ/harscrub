/**
 * Rule model: the built-in sensitive-name lists, `harscrub.json`
 * loading with strict validation, and compilation into the
 * EffectiveRules value the engine runs with.
 *
 * Merging is additive-by-default: a rules file *extends* the built-ins
 * (`add`) or punches explicit holes in them (`keep`); it never silently
 * replaces the defaults, because a scrubber that forgets `authorization`
 * when a user adds one custom header would be a footgun.
 */

import { readFileSync } from "node:fs";
import { BUILTIN_PATTERNS, compileCustomPattern } from "./patterns.js";
import type {
  EffectiveRules,
  NameMatcher,
  RedactMode,
  RuleFile,
  TokenPattern,
} from "./types.js";

/** Request/response header names whose values are credentials. */
export const DEFAULT_HEADERS: readonly string[] = [
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "apikey",
  "x-auth-token",
  "x-auth",
  "x-access-token",
  "x-session-id",
  "x-session-token",
  "x-csrf-token",
  "x-xsrf-token",
  "x-amz-security-token",
  "x-goog-api-key",
  "x-gitlab-token",
  "private-token",
  "x-vault-token",
  "x-functions-key",
  "ocp-apim-subscription-key",
  "x-shopify-access-token",
  "x-hub-signature",
  "x-hub-signature-256",
  "x-signature",
];

/** Query-string parameter names that carry credentials. */
export const DEFAULT_QUERY_PARAMS: readonly string[] = [
  "access_token",
  "refresh_token",
  "id_token",
  "token",
  "auth_token",
  "jwt",
  "bearer",
  "api_key",
  "api-key",
  "apikey",
  "key",
  "secret",
  "client_secret",
  "password",
  "passwd",
  "pwd",
  "auth",
  "session",
  "session_id",
  "sessionid",
  "sid",
  "signature",
  "sig",
  "otp",
  "code",
  "x-amz-signature",
  "x-amz-security-token",
];

/** JSON/form body keys that carry credentials, at any nesting depth. */
export const DEFAULT_BODY_KEYS: readonly string[] = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "client_secret",
  "access_token",
  "refresh_token",
  "id_token",
  "token",
  "auth_token",
  "session_token",
  "sessionid",
  "session_id",
  "authorization",
  "api_key",
  "apikey",
  "private_key",
  "secret_key",
  "code_verifier",
  "assertion",
  "otp",
  "pin",
  "card_number",
  "cvv",
];

const VALID_MODES: readonly RedactMode[] = ["mask", "hash", "remove"];

/** Escape a literal for embedding in a RegExp source. */
function escapeRe(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Compile names into a matcher. Names containing `*` become globs
 * (`x-internal-*` matches `x-internal-auth`); everything else is a
 * case-insensitive literal.
 */
export function compileNames(names: readonly string[]): NameMatcher {
  const literals = new Set<string>();
  const globs: RegExp[] = [];
  for (const name of names) {
    const lower = name.toLowerCase();
    if (lower.includes("*")) {
      const source = lower.split("*").map(escapeRe).join(".*");
      globs.push(new RegExp(`^${source}$`));
    } else {
      literals.add(lower);
    }
  }
  return { literals, globs };
}

/** Test a name (case-insensitively) against a matcher. */
export function matchesName(matcher: NameMatcher, name: string): boolean {
  const lower = name.toLowerCase();
  if (matcher.literals.has(lower)) return true;
  return matcher.globs.some((g) => g.test(lower));
}

/* ------------------------------------------------------------------ */
/* Rules-file validation                                               */
/* ------------------------------------------------------------------ */

function expectStringArray(value: unknown, path: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new Error(`rules file: "${path}" must be an array of strings`);
  }
  return value as string[];
}

function expectKeys(value: unknown, path: string, allowed: readonly string[]): void {
  if (value === undefined) return;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`rules file: "${path}" must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new Error(
        `rules file: unknown key "${path}.${key}" (allowed: ${allowed.join(", ")})`,
      );
    }
  }
}

/**
 * Validate a parsed rules file. Unknown keys are hard errors: a typo
 * like `"header"` for `"headers"` must not silently leave credentials
 * in the output.
 */
export function validateRuleFile(raw: unknown): RuleFile {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("rules file: top level must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  expectKeys(obj, "$", [
    "mode",
    "salt",
    "headers",
    "cookies",
    "queryParams",
    "bodyKeys",
    "patterns",
    "dropContent",
  ]);
  if (obj.mode !== undefined && !VALID_MODES.includes(obj.mode as RedactMode)) {
    throw new Error(`rules file: "mode" must be one of ${VALID_MODES.join(", ")}`);
  }
  if (obj.salt !== undefined && typeof obj.salt !== "string") {
    throw new Error(`rules file: "salt" must be a string`);
  }
  if (obj.dropContent !== undefined && typeof obj.dropContent !== "boolean") {
    throw new Error(`rules file: "dropContent" must be a boolean`);
  }
  expectKeys(obj.headers, "headers", ["add", "keep"]);
  expectKeys(obj.cookies, "cookies", ["keep"]);
  expectKeys(obj.queryParams, "queryParams", ["add", "keep"]);
  expectKeys(obj.bodyKeys, "bodyKeys", ["add", "keep"]);
  expectKeys(obj.patterns, "patterns", ["disable", "custom"]);

  const patterns = obj.patterns as Record<string, unknown> | undefined;
  if (patterns?.custom !== undefined) {
    if (!Array.isArray(patterns.custom)) {
      throw new Error(`rules file: "patterns.custom" must be an array`);
    }
    for (const [i, entry] of (patterns.custom as unknown[]).entries()) {
      if (typeof entry !== "object" || entry === null) {
        throw new Error(`rules file: "patterns.custom[${i}]" must be an object`);
      }
      const e = entry as Record<string, unknown>;
      expectKeys(e, `patterns.custom[${i}]`, ["name", "regex", "flags"]);
      if (typeof e.name !== "string" || e.name === "") {
        throw new Error(`rules file: "patterns.custom[${i}].name" must be a non-empty string`);
      }
      if (typeof e.regex !== "string" || e.regex === "") {
        throw new Error(`rules file: "patterns.custom[${i}].regex" must be a non-empty string`);
      }
      if (e.flags !== undefined && typeof e.flags !== "string") {
        throw new Error(`rules file: "patterns.custom[${i}].flags" must be a string`);
      }
    }
  }
  // Cross-field sanity for the nested string arrays.
  for (const section of ["headers", "queryParams", "bodyKeys"] as const) {
    const s = obj[section] as Record<string, unknown> | undefined;
    expectStringArray(s?.add, `${section}.add`);
    expectStringArray(s?.keep, `${section}.keep`);
  }
  expectStringArray((obj.cookies as Record<string, unknown> | undefined)?.keep, "cookies.keep");
  expectStringArray(patterns?.disable, "patterns.disable");
  return obj as RuleFile;
}

/** Read + parse + validate a rules file from disk. */
export function loadRuleFile(path: string): RuleFile {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(`rules file: cannot read ${path}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`rules file: ${path} is not valid JSON: ${(err as Error).message}`);
  }
  return validateRuleFile(raw);
}

/* ------------------------------------------------------------------ */
/* Compilation                                                         */
/* ------------------------------------------------------------------ */

/** Options layered on top of the rules file by CLI flags. */
export interface RuleOverrides {
  mode?: RedactMode;
  salt?: string;
  dropContent?: boolean;
}

/**
 * Merge built-ins + rules file + CLI overrides into the compiled rule
 * set. Precedence, lowest to highest: defaults, rules file, CLI flags.
 */
export function buildRules(file: RuleFile = {}, overrides: RuleOverrides = {}): EffectiveRules {
  const disabled = new Set((file.patterns?.disable ?? []).map((n) => n.toLowerCase()));
  for (const name of disabled) {
    if (!BUILTIN_PATTERNS.some((p) => p.name === name)) {
      throw new Error(
        `rules file: "patterns.disable" names unknown pattern "${name}" ` +
          `(known: ${BUILTIN_PATTERNS.map((p) => p.name).join(", ")})`,
      );
    }
  }
  const patterns: TokenPattern[] = BUILTIN_PATTERNS.filter((p) => !disabled.has(p.name));
  for (const custom of file.patterns?.custom ?? []) {
    patterns.push(compileCustomPattern(custom));
  }
  return {
    mode: overrides.mode ?? file.mode ?? "mask",
    salt: overrides.salt ?? file.salt ?? "",
    headers: compileNames([...DEFAULT_HEADERS, ...(file.headers?.add ?? [])]),
    headerKeep: compileNames(file.headers?.keep ?? []),
    cookieKeep: compileNames(file.cookies?.keep ?? []),
    queryParams: compileNames([...DEFAULT_QUERY_PARAMS, ...(file.queryParams?.add ?? [])]),
    queryKeep: compileNames(file.queryParams?.keep ?? []),
    bodyKeys: compileNames([...DEFAULT_BODY_KEYS, ...(file.bodyKeys?.add ?? [])]),
    bodyKeep: compileNames(file.bodyKeys?.keep ?? []),
    patterns,
    dropContent: overrides.dropContent ?? file.dropContent ?? false,
  };
}

/** The starter rules file written by `harscrub init`. */
export const STARTER_RULES = `{
  "mode": "mask",
  "salt": "",
  "headers": { "add": [], "keep": [] },
  "cookies": { "keep": [] },
  "queryParams": { "add": [], "keep": [] },
  "bodyKeys": { "add": [], "keep": [] },
  "patterns": { "disable": [], "custom": [] },
  "dropContent": false
}
`;
