/**
 * Shared types: a tolerant model of the HAR 1.2 format, the rule
 * configuration surface, and the findings the scrub engine emits.
 *
 * The HAR types are deliberately loose (`extra` fields survive as-is):
 * real captures from Chrome, Firefox and proxies carry vendor fields
 * (`_initiator`, `_resourceType`, …) that a scrubber must pass through
 * untouched — dropping them would break the "still loads in DevTools"
 * promise.
 */

/** A name/value pair as used by headers, query params and form params. */
export interface NameValue {
  name: string;
  value: string;
  [extra: string]: unknown;
}

/** A cookie record from `request.cookies` / `response.cookies`. */
export interface HarCookie {
  name: string;
  value: string;
  [extra: string]: unknown;
}

export interface HarPostData {
  mimeType?: string;
  text?: string;
  params?: NameValue[];
  [extra: string]: unknown;
}

export interface HarContent {
  size?: number;
  mimeType?: string;
  text?: string;
  encoding?: string;
  comment?: string;
  [extra: string]: unknown;
}

export interface HarRequest {
  method?: string;
  url?: string;
  headers?: NameValue[];
  queryString?: NameValue[];
  cookies?: HarCookie[];
  postData?: HarPostData;
  headersSize?: number;
  bodySize?: number;
  [extra: string]: unknown;
}

export interface HarResponse {
  status?: number;
  headers?: NameValue[];
  cookies?: HarCookie[];
  content?: HarContent;
  redirectURL?: string;
  headersSize?: number;
  bodySize?: number;
  [extra: string]: unknown;
}

export interface HarEntry {
  request?: HarRequest;
  response?: HarResponse;
  [extra: string]: unknown;
}

export interface HarLog {
  version?: string;
  entries?: HarEntry[];
  [extra: string]: unknown;
}

export interface Har {
  log?: HarLog;
  [extra: string]: unknown;
}

/** How a matched value is rewritten. */
export type RedactMode = "mask" | "hash" | "remove";

/** A custom regex pattern supplied via the rules file. */
export interface CustomPattern {
  name: string;
  regex: string;
  flags?: string;
}

/** Shape of a `harscrub.json` rules file. Every field is optional. */
export interface RuleFile {
  mode?: RedactMode;
  salt?: string;
  headers?: { add?: string[]; keep?: string[] };
  cookies?: { keep?: string[] };
  queryParams?: { add?: string[]; keep?: string[] };
  bodyKeys?: { add?: string[]; keep?: string[] };
  patterns?: { disable?: string[]; custom?: CustomPattern[] };
  dropContent?: boolean;
}

/** A compiled name matcher: literal names plus `*` globs. */
export interface NameMatcher {
  /** Lower-cased literal names. */
  literals: Set<string>;
  /** Compiled glob patterns (from names containing `*`). */
  globs: RegExp[];
}

/** A compiled token-detector pattern. */
export interface TokenPattern {
  name: string;
  description: string;
  /** Must be constructed with the `g` flag. */
  re: RegExp;
  /**
   * When the regex uses groups: group 1 is a prefix to keep verbatim
   * (e.g. `Bearer `), group 2 is the secret. Without groups the whole
   * match is the secret.
   */
  grouped: boolean;
  /** True for built-ins, false for user-supplied customs. */
  builtin: boolean;
}

/** Fully merged, compiled rule set the engine runs with. */
export interface EffectiveRules {
  mode: RedactMode;
  salt: string;
  headers: NameMatcher;
  headerKeep: NameMatcher;
  cookieKeep: NameMatcher;
  queryParams: NameMatcher;
  queryKeep: NameMatcher;
  bodyKeys: NameMatcher;
  bodyKeep: NameMatcher;
  patterns: TokenPattern[];
  dropContent: boolean;
}

/** Where in the entry a redaction happened. */
export type FindingLocation =
  | "request.url"
  | "request.headers"
  | "request.cookies"
  | "request.queryString"
  | "request.postData"
  | "request.postData.params"
  | "response.headers"
  | "response.cookies"
  | "response.content"
  | "response.redirectURL";

/** One redacted (or, in audit mode, redactable) value. */
export interface Finding {
  /** 0-based index into `log.entries`. */
  entry: number;
  location: FindingLocation;
  /**
   * What triggered the rule: `header`, `cookie`, `query-param`,
   * `body-key`, `url-credentials`, or `pattern:<name>`.
   */
  rule: string;
  /** The header/cookie/param/key name, or the pattern name. */
  item: string;
  action: RedactMode;
  /** Truncated, non-reversible preview of the original value. */
  preview: string;
}

/** Result of a scrub run. */
export interface ScrubResult {
  har: Har;
  findings: Finding[];
}
