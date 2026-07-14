// Argument parsing: command dispatch, strict flag validation, and the
// cross-flag rules that keep dangerous combinations from half-working.
import test from "node:test";
import assert from "node:assert/strict";

import { parseArgs, UsageError } from "../dist/cliargs.js";

test("bare file argument implies the scrub command", () => {
  const opts = parseArgs(["capture.har"]);
  assert.equal(opts.command, "scrub");
  assert.equal(opts.input, "capture.har");
});

test("explicit commands claim the first positional", () => {
  assert.equal(parseArgs(["audit", "x.har"]).command, "audit");
  assert.equal(parseArgs(["audit", "x.har"]).input, "x.har");
  assert.equal(parseArgs(["rules"]).command, "rules");
  assert.equal(parseArgs(["init"]).command, "init");
});

test("no input defaults to stdin for scrub and audit", () => {
  assert.equal(parseArgs([]).input, "-");
  assert.equal(parseArgs(["audit"]).input, "-");
  assert.equal(parseArgs(["-"]).input, "-");
});

test("--help and --version win regardless of position", () => {
  assert.equal(parseArgs(["scrub", "x.har", "--help"]).command, "help");
  assert.equal(parseArgs(["-V"]).command, "version");
});

test("value-taking flags are parsed and validated", () => {
  const opts = parseArgs(["scrub", "x.har", "-o", "out.har", "--mode", "hash", "--salt", "s", "--rules", "r.json"]);
  assert.equal(opts.output, "out.har");
  assert.equal(opts.mode, "hash");
  assert.equal(opts.salt, "s");
  assert.equal(opts.rulesPath, "r.json");
  assert.throws(() => parseArgs(["--mode"]), UsageError);
  assert.throws(() => parseArgs(["--mode", "shred"]), /--mode must be one of/);
  // Boolean flags default off and toggle on.
  const defaults = parseArgs(["x.har"]);
  assert.deepEqual(
    [defaults.inPlace, defaults.noConfig, defaults.dropContent, defaults.quiet],
    [false, false, false, false],
  );
  const on = parseArgs(["x.har", "--no-config", "--drop-content", "-q"]);
  assert.deepEqual([on.noConfig, on.dropContent, on.quiet], [true, true, true]);
});

test("unknown flags and extra positionals are fatal", () => {
  assert.throws(() => parseArgs(["--modes", "hash"]), /unknown option: --modes/);
  assert.throws(() => parseArgs(["scrub", "a.har", "b.har"]), /unexpected argument: b.har/);
  assert.throws(() => parseArgs(["rules", "x.har"]), /takes no positional/);
});

test("--in-place: scrub-only, conflicts with -o, needs a real file", () => {
  assert.equal(parseArgs(["scrub", "x.har", "--in-place"]).inPlace, true);
  assert.throws(() => parseArgs(["audit", "x.har", "--in-place"]), /only applies to scrub/);
  assert.throws(() => parseArgs(["scrub", "x.har", "-i", "-o", "y.har"]), /conflicts with -o/);
  assert.throws(() => parseArgs(["scrub", "-", "--in-place"]), /needs a file/);
});

test("--json is limited to audit and rules; --report to scrub", () => {
  assert.equal(parseArgs(["audit", "x.har", "--json"]).json, true);
  assert.throws(() => parseArgs(["scrub", "x.har", "--json"]), /--json only applies/);
  assert.equal(parseArgs(["scrub", "x.har", "--report"]).report, true);
  assert.throws(() => parseArgs(["audit", "x.har", "--report"]), /--report only applies/);
});

test("init rejects rule-evaluation flags that would do nothing", () => {
  assert.throws(() => parseArgs(["init", "--mode", "hash"]), /does not apply to init/);
  assert.throws(() => parseArgs(["init", "--drop-content"]), /does not apply to init/);
  const opts = parseArgs(["init", "-o", "custom.json"]);
  assert.equal(opts.output, "custom.json");
});
