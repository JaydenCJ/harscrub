/**
 * Built-in token detectors: regexes for credential formats that are
 * recognizable by shape alone, applied to free text (header values,
 * bodies, URLs) after the name-based rules have run.
 *
 * Design rules for this list:
 *   - Every pattern must anchor on a vendor prefix or a structural
 *     giveaway (`eyJ` is base64 for `{"`), never on entropy guesses —
 *     false positives in a scrubber destroy the capture's usefulness.
 *   - Patterns with a `(prefix)(secret)` group pair keep the prefix
 *     verbatim so `Bearer eyJ…` stays recognizably a bearer scheme.
 *   - Placeholders (`[REDACTED…]`) must never re-match, keeping the
 *     scrub idempotent.
 */

import type { CustomPattern, TokenPattern } from "./types.js";
import type { Redactor } from "./placeholder.js";

/** Build a TokenPattern, normalizing flags to include `g`. */
function pattern(
  name: string,
  description: string,
  source: string,
  grouped = false,
  flags = "",
): TokenPattern {
  return { name, description, re: new RegExp(source, `g${flags}`), grouped, builtin: true };
}

/** The built-in detector set, in application order. */
export const BUILTIN_PATTERNS: readonly TokenPattern[] = [
  pattern(
    "private-key",
    "PEM private key blocks (RSA, EC, OpenSSH, PKCS#8)",
    String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`,
  ),
  pattern(
    "jwt",
    "JSON Web Tokens (three dot-separated base64url segments starting eyJ)",
    String.raw`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}(?![A-Za-z0-9_-])`,
  ),
  pattern(
    "bearer-token",
    "credentials following a Bearer/Token auth scheme",
    String.raw`\b([Bb]earer\s+|[Tt]oken\s+)([A-Za-z0-9._~+/=-]{16,})`,
    true,
  ),
  pattern(
    "basic-credentials",
    "base64 credentials following a Basic auth scheme",
    String.raw`\b([Bb]asic\s+)([A-Za-z0-9+/=]{8,})`,
    true,
  ),
  pattern(
    "aws-access-key-id",
    "AWS access key IDs (AKIA/ASIA + 16 chars)",
    String.raw`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
  ),
  pattern(
    "aws-secret-key",
    "AWS secret access keys, anchored on an aws_secret…-style key name",
    String.raw`\b(aws_?secret(?:_?access)?(?:_?key)?["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])`,
    true,
    "i",
  ),
  pattern(
    "github-token",
    "GitHub personal access and app tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)",
    String.raw`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b`,
  ),
  pattern(
    "gitlab-token",
    "GitLab personal access tokens (glpat-)",
    String.raw`\bglpat-[A-Za-z0-9_-]{20,}\b`,
  ),
  pattern(
    "slack-token",
    "Slack bot/user/app tokens (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-)",
    String.raw`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`,
  ),
  pattern(
    "stripe-key",
    "Stripe secret/restricted keys (sk_live_/sk_test_/rk_live_/rk_test_)",
    String.raw`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b`,
  ),
  pattern(
    "sk-api-key",
    "API keys of the sk- prefix family used by several AI/SaaS vendors",
    String.raw`\bsk-[A-Za-z0-9_-]{20,}\b`,
  ),
  pattern(
    "google-api-key",
    "Google API keys (AIza + 35 chars)",
    String.raw`\bAIza[0-9A-Za-z_-]{35}\b`,
  ),
  pattern(
    "sendgrid-key",
    "SendGrid API keys (SG. + two dot-separated segments)",
    String.raw`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`,
  ),
  pattern(
    "npm-token",
    "npm automation tokens (npm_ + 36 chars)",
    String.raw`\bnpm_[A-Za-z0-9]{36}\b`,
  ),
];

/** Compile a user-supplied custom pattern, validating the regex. */
export function compileCustomPattern(custom: CustomPattern): TokenPattern {
  const flags = custom.flags ?? "";
  if (/[^imsu]/.test(flags)) {
    throw new Error(
      `pattern "${custom.name}": flags may only contain "imsu" (got "${flags}")`,
    );
  }
  let re: RegExp;
  try {
    re = new RegExp(custom.regex, `g${flags}`);
  } catch (err) {
    throw new Error(`pattern "${custom.name}": invalid regex: ${(err as Error).message}`);
  }
  return {
    name: custom.name,
    description: "custom pattern from rules file",
    re,
    grouped: false,
    builtin: false,
  };
}

/** One pattern hit inside a scanned string. */
export interface PatternHit {
  pattern: string;
  /** The secret portion that was replaced. */
  secret: string;
}

/**
 * Scan free text with every pattern, replacing secrets with
 * placeholders. Returns the rewritten text plus one hit per replaced
 * token. Patterns run in order; a placeholder inserted by an earlier
 * pattern is never re-matched by a later one.
 */
export function scanText(
  text: string,
  patterns: readonly TokenPattern[],
  redactor: Redactor,
): { text: string; hits: PatternHit[] } {
  let out = text;
  const hits: PatternHit[] = [];
  for (const p of patterns) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (...args: unknown[]) => {
      const match = args[0] as string;
      let keep = "";
      let secret = match;
      if (p.grouped) {
        keep = (args[1] as string | undefined) ?? "";
        secret = (args[2] as string | undefined) ?? match.slice(keep.length);
      }
      hits.push({ pattern: p.name, secret });
      return keep + redactor.placeholder(secret);
    });
  }
  return { text: out, hits };
}
