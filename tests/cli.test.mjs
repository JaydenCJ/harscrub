// CLI integration: the built binary, run against real files in fresh
// temp dirs — exit codes, stdin/stdout piping, config discovery,
// in-place rewrites and the init/rules subcommands.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { JWT, makeDir, makeEntry, makeHar, runCli } from "./helpers.mjs";
import { VERSION } from "../dist/version.js";

const secretHar = () =>
  makeHar([
    makeEntry({
      request: {
        url: "https://api.example.test/v1/me?access_token=tok-123",
        headers: [{ name: "authorization", value: `Bearer ${JWT}` }],
        queryString: [{ name: "access_token", value: "tok-123" }],
      },
    }),
  ]);

const cleanHar = () => makeHar([makeEntry()]);

test("--version matches package.json; --help documents every command", () => {
  const version = runCli(["--version"]);
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), VERSION);
  assert.equal(
    version.stdout.trim(),
    JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version,
  );
  const help = runCli(["--help"]);
  assert.equal(help.status, 0);
  for (const word of ["scrub", "audit", "rules", "init", "--mode", "Exit codes"]) {
    assert.ok(help.stdout.includes(word), `help missing ${word}`);
  }
});

test("scrub reads stdin and writes a scrubbed HAR to stdout", () => {
  const { status, stdout, stderr } = runCli(["scrub", "-"], {
    input: JSON.stringify(secretHar()),
  });
  assert.equal(status, 0);
  assert.ok(!stdout.includes("tok-123"));
  assert.ok(!stdout.includes(JWT));
  assert.match(stderr, /values redacted across 1 entry/);
  const har = JSON.parse(stdout);
  assert.equal(har.log.entries.length, 1);
});

test("scrub -o writes a file, --in-place rewrites, --quiet silences stderr", () => {
  const { dir, cleanup } = makeDir({ "in.har": secretHar() });
  try {
    const out = join(dir, "out.har");
    const toFile = runCli(["scrub", "in.har", "-o", out, "--quiet"], { cwd: dir });
    assert.equal(toFile.status, 0);
    assert.equal(toFile.stderr, "");
    assert.ok(!readFileSync(out, "utf8").includes("tok-123"));
    const inPlace = runCli(["scrub", "in.har", "--in-place", "-q"], { cwd: dir });
    assert.equal(inPlace.status, 0);
    assert.ok(!readFileSync(join(dir, "in.har"), "utf8").includes("tok-123"));
  } finally {
    cleanup();
  }
});

test("pretty input stays pretty; compact input stays compact", () => {
  const pretty = runCli(["scrub", "-", "-q"], { input: JSON.stringify(secretHar(), null, 2) });
  assert.ok(pretty.stdout.includes('\n  "log"'), "2-space indent preserved");
  const compact = runCli(["scrub", "-", "-q"], { input: JSON.stringify(secretHar()) });
  assert.equal(compact.stdout.trim().split("\n").length, 1, "compact stays one line");
  const tabbed = runCli(["scrub", "-", "-q"], { input: JSON.stringify(secretHar(), null, "\t") });
  assert.ok(tabbed.stdout.includes('\n\t"log"'), "tab indent preserved, not converted to spaces");
});

test("audit exits 1 with a findings table on secrets, 0 on a clean capture", () => {
  const dirty = runCli(["audit", "-"], { input: JSON.stringify(secretHar()) });
  assert.equal(dirty.status, 1);
  assert.match(dirty.stdout, /ENTRY\s+LOCATION\s+RULE/);
  assert.match(dirty.stdout, /query-param\s+access_token/);
  assert.ok(!dirty.stdout.includes(JWT), "audit shows truncated previews, never a full token");
  assert.match(dirty.stdout, /eyJ[A-Za-z0-9]+…/, "previews keep a recognizable stem");
  const clean = runCli(["audit", "-"], { input: JSON.stringify(cleanHar()) });
  assert.equal(clean.status, 0);
  assert.match(clean.stdout, /no redactable values found/);
});

test("audit --json emits a machine-readable report", () => {
  const { status, stdout } = runCli(["audit", "-", "--json"], {
    input: JSON.stringify(secretHar()),
  });
  assert.equal(status, 1);
  const doc = JSON.parse(stdout);
  assert.ok(doc.summary.total >= 2);
  assert.equal(typeof doc.summary.byRule, "object");
});

test("bad input and bad flags exit 2 with a clear message", () => {
  const bad = runCli(["scrub", "-"], { input: "not json at all" });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /not valid JSON/);
  const notHar = runCli(["audit", "-"], { input: '{"some":"json"}' });
  assert.equal(notHar.status, 2);
  assert.match(notHar.stderr, /missing log\.entries/);
  const missing = runCli(["scrub", "no-such-file.har"]);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /cannot read no-such-file.har/);
  const flag = runCli(["scrub", "x.har", "--modes", "hash"]);
  assert.equal(flag.status, 2);
  assert.match(flag.stderr, /unknown option: --modes/);
  assert.match(flag.stderr, /--help/);
});

test("init writes a starter rules file and refuses to overwrite", () => {
  const { dir, cleanup } = makeDir();
  try {
    const first = runCli(["init"], { cwd: dir });
    assert.equal(first.status, 0);
    assert.ok(existsSync(join(dir, "harscrub.json")));
    JSON.parse(readFileSync(join(dir, "harscrub.json"), "utf8"));
    const second = runCli(["init"], { cwd: dir });
    assert.equal(second.status, 2);
    assert.match(second.stderr, /refusing to overwrite/);
  } finally {
    cleanup();
  }
});

test("./harscrub.json is auto-discovered; --no-config ignores it", () => {
  const rules = { cookies: { keep: [] }, queryParams: { keep: ["access_token"] } };
  const { dir, cleanup } = makeDir({
    "harscrub.json": rules,
    "in.har": secretHar(),
  });
  try {
    const withConfig = runCli(["scrub", "in.har"], { cwd: dir });
    assert.match(withConfig.stderr, /rules from .*harscrub\.json/);
    assert.ok(withConfig.stdout.includes("tok-123"), "keep-listed param untouched");
    const without = runCli(["scrub", "in.har", "--no-config"], { cwd: dir });
    assert.ok(!without.stdout.includes("tok-123"), "--no-config restores defaults");
  } finally {
    cleanup();
  }
});

test("an invalid rules file is a hard error, not a silent fallback", () => {
  const { dir, cleanup } = makeDir({
    "bad.json": { headers: { include: ["x"] } },
    "in.har": secretHar(),
  });
  try {
    const { status, stderr } = runCli(["scrub", "in.har", "--rules", "bad.json"], { cwd: dir });
    assert.equal(status, 2);
    assert.match(stderr, /unknown key "headers\.include"/);
  } finally {
    cleanup();
  }
});

test("rules lists the effective rule set, honoring the rules file", () => {
  const { dir, cleanup } = makeDir({
    "harscrub.json": { headers: { add: ["x-acme-token"] }, patterns: { disable: ["sk-api-key"] } },
  });
  try {
    const { status, stdout } = runCli(["rules"], { cwd: dir });
    assert.equal(status, 0);
    assert.ok(stdout.includes("x-acme-token"));
    assert.ok(stdout.includes("authorization"), "defaults still listed");
    assert.ok(!stdout.match(/^\s+sk-api-key/m), "disabled pattern absent");
    const json = runCli(["rules", "--json"], { cwd: dir });
    const doc = JSON.parse(json.stdout);
    assert.ok(doc.headers.includes("x-acme-token"));
    assert.ok(!doc.patterns.some((p) => p.name === "sk-api-key"));
  } finally {
    cleanup();
  }
});

test("scrub --report prints a per-rule table on stderr", () => {
  const { status, stderr } = runCli(["scrub", "-", "--report"], {
    input: JSON.stringify(secretHar()),
  });
  assert.equal(status, 0);
  assert.match(stderr, /RULE\s+COUNT/);
  assert.match(stderr, /query-param\s+2/);
});

test("--mode hash --salt is stable across two runs", () => {
  const input = JSON.stringify(secretHar());
  const a = runCli(["scrub", "-", "-q", "--mode", "hash", "--salt", "s1"], { input });
  const b = runCli(["scrub", "-", "-q", "--mode", "hash", "--salt", "s1"], { input });
  assert.equal(a.stdout, b.stdout);
  const c = runCli(["scrub", "-", "-q", "--mode", "hash", "--salt", "s2"], { input });
  assert.notEqual(a.stdout, c.stdout, "different salt, different tags");
});

test("--drop-content removes response bodies via the CLI", () => {
  const har = makeHar([
    makeEntry({ response: { content: { size: 5, mimeType: "text/plain", text: "hello" } } }),
  ]);
  const { status, stdout } = runCli(["scrub", "-", "-q", "--drop-content"], {
    input: JSON.stringify(har),
  });
  assert.equal(status, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.log.entries[0].response.content.text, undefined);
  assert.match(out.log.entries[0].response.content.comment, /removed by harscrub/);
});
