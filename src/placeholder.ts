/**
 * Placeholder generation — the one place that decides what a redacted
 * value looks like.
 *
 * Three modes:
 *   - `mask`   → the fixed string `[REDACTED]`.
 *   - `hash`   → `[REDACTED:xxxxxxxx]`, the first 8 hex chars of
 *                SHA-256(salt + "\n" + value). Deterministic, so the
 *                same session token produces the same tag everywhere it
 *                appears — a reader can still correlate requests without
 *                ever seeing the secret.
 *   - `remove` → the carrying element (header, param, cookie, JSON key)
 *                is dropped entirely; handled by the callers, not here.
 *
 * Placeholders are shaped so no built-in token pattern can re-match
 * them, which is what makes scrubbing idempotent.
 */

import { createHash } from "node:crypto";
import type { RedactMode } from "./types.js";

/** The fixed placeholder used by `mask` mode. */
export const MASK = "[REDACTED]";

/** Matches any placeholder this tool has ever produced. */
const PLACEHOLDER_RE = /^\[REDACTED(?::[0-9a-f]{8})?\]$/;

/**
 * A bound redactor: mode + salt captured once, then applied to many
 * values. Keeping it a value (not module state) keeps the engine pure.
 */
export interface Redactor {
  mode: RedactMode;
  placeholder(value: string): string;
}

/** First 8 hex chars of SHA-256 over the salted value. */
export function hashTag(value: string, salt: string): string {
  return createHash("sha256").update(`${salt}\n${value}`).digest("hex").slice(0, 8);
}

/** Build the placeholder string for one value under a mode + salt. */
export function placeholderFor(value: string, mode: RedactMode, salt: string): string {
  if (mode === "hash") return `[REDACTED:${hashTag(value, salt)}]`;
  return MASK;
}

/**
 * True when a value is already a harscrub placeholder. Used to make
 * `hash` mode idempotent: re-hashing `[REDACTED:ab12cd34]` would mint a
 * new tag on every run and break diffs between two scrubbed captures.
 */
export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

/** Construct a Redactor for the run. */
export function makeRedactor(mode: RedactMode, salt: string): Redactor {
  return {
    mode,
    placeholder: (value: string) => placeholderFor(value, mode, salt),
  };
}

/**
 * Truncated, non-reversible preview for audit output: enough to
 * recognize which secret is meant, never enough to replay it.
 */
export function preview(value: string, max = 12): string {
  const flat = value.replace(/\s+/g, " ");
  if (flat.length <= max) return flat;
  return `${flat.slice(0, max)}…`;
}
