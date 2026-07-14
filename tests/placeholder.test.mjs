// Placeholder generation: the mask/hash formats, determinism, salt
// separation, and the idempotency detector everything else relies on.
import test from "node:test";
import assert from "node:assert/strict";

import {
  MASK,
  hashTag,
  isPlaceholder,
  makeRedactor,
  placeholderFor,
  preview,
} from "../dist/placeholder.js";

test("mask mode always yields the fixed [REDACTED] marker", () => {
  assert.equal(placeholderFor("hunter2", "mask", ""), MASK);
  assert.equal(placeholderFor("another secret", "mask", "salted"), MASK);
});

test("hash mode is deterministic: same value + salt, same tag", () => {
  const a = placeholderFor("session-abc123", "hash", "");
  const b = placeholderFor("session-abc123", "hash", "");
  assert.equal(a, b);
  assert.match(a, /^\[REDACTED:[0-9a-f]{8}\]$/);
  const tag = hashTag("value", "salt");
  assert.match(tag, /^[0-9a-f]{8}$/);
  assert.equal(tag, hashTag("value", "salt"));
});

test("hash mode separates values and salts", () => {
  // Different secrets must not collide, and the same secret under a
  // different salt must change — otherwise a public rainbow of common
  // tokens would identify hashed values across reports.
  assert.notEqual(placeholderFor("token-a", "hash", ""), placeholderFor("token-b", "hash", ""));
  assert.notEqual(placeholderFor("token-a", "hash", "s1"), placeholderFor("token-a", "hash", "s2"));
});

test("isPlaceholder recognizes both placeholder shapes and nothing else", () => {
  assert.ok(isPlaceholder("[REDACTED]"));
  assert.ok(isPlaceholder("[REDACTED:ab12cd34]"));
  assert.ok(!isPlaceholder("REDACTED"));
  assert.ok(!isPlaceholder("[REDACTED:xyz]")); // not hex
  assert.ok(!isPlaceholder("[REDACTED:ab12cd34] trailing"));
  assert.ok(!isPlaceholder("Bearer [REDACTED]"));
});

test("makeRedactor binds mode and salt", () => {
  const masker = makeRedactor("mask", "");
  const hasher = makeRedactor("hash", "pepper");
  assert.equal(masker.placeholder("x"), MASK);
  assert.equal(hasher.placeholder("x"), placeholderFor("x", "hash", "pepper"));
  assert.equal(hasher.mode, "hash");
});

test("preview truncates and flattens whitespace, never echoing the full secret", () => {
  assert.equal(preview("short"), "short");
  const long = preview("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(long, "aaaaaaaaaaaa…");
  assert.equal(preview("line1\nline2\tend", 20), "line1 line2 end");
});
