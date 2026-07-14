#!/usr/bin/env node
/**
 * CLI entry point: wires argument parsing, rules loading, the scrub
 * engine and reporting to stdin/stdout/files. All I/O lives here; every
 * module below it is pure and unit-testable.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs, UsageError, USAGE, type CliOptions } from "./cliargs.js";
import {
  buildRules,
  loadRuleFile,
  STARTER_RULES,
  DEFAULT_BODY_KEYS,
  DEFAULT_HEADERS,
  DEFAULT_QUERY_PARAMS,
} from "./rules.js";
import { scrubHar } from "./scrub.js";
import { formatAudit, formatOneLine, formatSummaryTable, toJsonReport } from "./report.js";
import { VERSION } from "./version.js";
import type { EffectiveRules, Har, RuleFile } from "./types.js";

/** Read the input document: a path, or stdin for `-`. */
function readInput(input: string): string {
  if (input === "-") return readFileSync(0, "utf8");
  return readFileSync(input, "utf8");
}

/** Parse and structurally check the HAR document. */
function parseHar(text: string): Har {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new UsageError(`input is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new UsageError("input is not a HAR file: top level must be an object");
  }
  const har = doc as Har;
  if (!har.log || typeof har.log !== "object" || !Array.isArray(har.log.entries)) {
    throw new UsageError("input is not a HAR file: missing log.entries");
  }
  return har;
}

/** Serialize the HAR, keeping the input's compact/pretty layout. */
function serializeHar(har: Har, originalText: string): string {
  const indentMatch = /\n([ \t]+)"/.exec(originalText);
  if (!indentMatch || indentMatch[1] === undefined) return `${JSON.stringify(har)}\n`;
  // Reuse the detected indent string itself, so tabs stay tabs.
  return `${JSON.stringify(har, null, indentMatch[1])}\n`;
}

/** Locate + load the rules file: explicit flag, else ./harscrub.json. */
function resolveRules(opts: CliOptions): { rules: EffectiveRules; source: string | null } {
  let file: RuleFile = {};
  let source: string | null = null;
  if (opts.rulesPath !== undefined) {
    file = loadRuleFile(opts.rulesPath);
    source = opts.rulesPath;
  } else if (!opts.noConfig) {
    const discovered = resolve(process.cwd(), "harscrub.json");
    if (existsSync(discovered)) {
      file = loadRuleFile(discovered);
      source = discovered;
    }
  }
  const rules = buildRules(file, {
    mode: opts.mode,
    salt: opts.salt,
    dropContent: opts.dropContent ? true : undefined,
  });
  return { rules, source };
}

/** Same merge the compiler applies, for display purposes. */
function mergedNames(defaults: readonly string[], add: string[] | undefined): string[] {
  return [...new Set([...defaults, ...(add ?? [])])].sort();
}

function runRulesCommand(opts: CliOptions): number {
  const { rules, source } = resolveRules(opts);
  let file: RuleFile = {};
  if (source !== null) file = loadRuleFile(source);

  const headers = mergedNames(DEFAULT_HEADERS, file.headers?.add);
  const queryParams = mergedNames(DEFAULT_QUERY_PARAMS, file.queryParams?.add);
  const bodyKeys = mergedNames(DEFAULT_BODY_KEYS, file.bodyKeys?.add);

  if (opts.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          mode: rules.mode,
          saltSet: rules.salt !== "",
          dropContent: rules.dropContent,
          rulesFile: source,
          headers,
          headerKeep: file.headers?.keep ?? [],
          cookiePolicy: "redact-all",
          cookieKeep: file.cookies?.keep ?? [],
          queryParams,
          queryKeep: file.queryParams?.keep ?? [],
          bodyKeys,
          bodyKeep: file.bodyKeys?.keep ?? [],
          patterns: rules.patterns.map((p) => ({
            name: p.name,
            description: p.description,
            builtin: p.builtin,
          })),
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  }

  const lines: string[] = [];
  lines.push(`mode          ${rules.mode}`);
  lines.push(`salt          ${rules.salt === "" ? "(none)" : "(set)"}`);
  lines.push(`drop content  ${rules.dropContent ? "yes" : "no"}`);
  lines.push(`rules file    ${source ?? "(built-in defaults only)"}`);
  lines.push("");
  lines.push(`headers (${headers.length}): ${headers.join(", ")}`);
  const keptCookies = file.cookies?.keep ?? [];
  lines.push(
    `cookies: all values redacted${keptCookies.length > 0 ? `, kept: ${keptCookies.join(", ")}` : ""}`,
  );
  lines.push(`query params (${queryParams.length}): ${queryParams.join(", ")}`);
  lines.push(`body keys (${bodyKeys.length}): ${bodyKeys.join(", ")}`);
  lines.push("");
  lines.push(`patterns (${rules.patterns.length}):`);
  const width = Math.max(...rules.patterns.map((p) => p.name.length));
  for (const p of rules.patterns) {
    lines.push(`  ${p.name.padEnd(width)}  ${p.description}`);
  }
  process.stdout.write(`${lines.join("\n")}\n`);
  return 0;
}

function runInit(opts: CliOptions): number {
  const path = opts.output ?? "harscrub.json";
  if (existsSync(path)) {
    throw new UsageError(`refusing to overwrite existing ${path}`);
  }
  writeFileSync(path, STARTER_RULES);
  process.stderr.write(`harscrub: wrote ${path}\n`);
  return 0;
}

function runScrub(opts: CliOptions): number {
  const { rules, source } = resolveRules(opts);
  const input = opts.input ?? "-";
  let text: string;
  try {
    text = readInput(input);
  } catch {
    throw new UsageError(`cannot read ${input === "-" ? "stdin" : input}`);
  }
  const har = parseHar(text);
  const { har: scrubbed, findings } = scrubHar(har, rules);
  const out = serializeHar(scrubbed, text);

  if (opts.inPlace) {
    writeFileSync(input, out);
  } else if (opts.output !== undefined) {
    writeFileSync(opts.output, out);
  } else {
    process.stdout.write(out);
  }

  if (!opts.quiet) {
    if (source !== null) process.stderr.write(`harscrub: rules from ${source}\n`);
    process.stderr.write(`${formatOneLine(findings, rules.mode)}\n`);
  }
  if (opts.report) {
    process.stderr.write(formatSummaryTable(findings));
  }
  return 0;
}

function runAudit(opts: CliOptions): number {
  const { rules } = resolveRules(opts);
  const input = opts.input ?? "-";
  let text: string;
  try {
    text = readInput(input);
  } catch {
    throw new UsageError(`cannot read ${input === "-" ? "stdin" : input}`);
  }
  const har = parseHar(text);
  const findings = scrubHar(har, rules).findings;
  process.stdout.write(opts.json ? toJsonReport(findings) : formatAudit(findings));
  return findings.length > 0 ? 1 : 0;
}

/** Run the CLI; returns the process exit code. */
export function run(argv: string[]): number {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`harscrub: ${err.message}\n`);
      process.stderr.write(`Run "harscrub --help" for usage.\n`);
      return 2;
    }
    throw err;
  }
  try {
    switch (opts.command) {
      case "help":
        process.stdout.write(USAGE);
        return 0;
      case "version":
        process.stdout.write(`${VERSION}\n`);
        return 0;
      case "init":
        return runInit(opts);
      case "rules":
        return runRulesCommand(opts);
      case "audit":
        return runAudit(opts);
      case "scrub":
        return runScrub(opts);
    }
  } catch (err) {
    if (err instanceof UsageError || err instanceof Error) {
      process.stderr.write(`harscrub: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
}

process.exitCode = run(process.argv.slice(2));
