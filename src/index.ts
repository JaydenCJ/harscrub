/**
 * Public programmatic API. Everything the CLI does is reachable from
 * here: build a rule set, scrub or audit a parsed HAR document, and
 * format the findings.
 *
 * ```js
 * import { buildRules, scrubHar } from "harscrub";
 * const { har, findings } = scrubHar(capture, buildRules());
 * ```
 */

export { scrubHar, auditHar, scrubCookieHeaderValue } from "./scrub.js";
export { scrubUrl } from "./urlscrub.js";
export {
  scrubBodyText,
  scrubJsonText,
  scrubFormText,
  isJsonMime,
  isFormMime,
} from "./bodyscrub.js";
export {
  buildRules,
  loadRuleFile,
  validateRuleFile,
  compileNames,
  matchesName,
  DEFAULT_HEADERS,
  DEFAULT_QUERY_PARAMS,
  DEFAULT_BODY_KEYS,
  STARTER_RULES,
} from "./rules.js";
export { BUILTIN_PATTERNS, compileCustomPattern, scanText } from "./patterns.js";
export {
  MASK,
  hashTag,
  placeholderFor,
  isPlaceholder,
  makeRedactor,
  preview,
} from "./placeholder.js";
export { summarize, formatAudit, formatSummaryTable, formatOneLine, toJsonReport } from "./report.js";
export { VERSION } from "./version.js";
export type {
  Har,
  HarLog,
  HarEntry,
  HarRequest,
  HarResponse,
  HarContent,
  HarPostData,
  HarCookie,
  NameValue,
  RedactMode,
  RuleFile,
  CustomPattern,
  EffectiveRules,
  TokenPattern,
  NameMatcher,
  Finding,
  FindingLocation,
  ScrubResult,
} from "./types.js";
