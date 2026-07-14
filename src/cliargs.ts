/**
 * Argument parsing for the CLI: a small, strict, dependency-free parser.
 * Unknown flags are hard errors (exit 2) — a mistyped `--modes hash`
 * silently falling back to defaults would ship a capture the user
 * believed was hashed.
 */

import type { RedactMode } from "./types.js";

export type Command = "scrub" | "audit" | "rules" | "init" | "help" | "version";

export interface CliOptions {
  command: Command;
  /** Input path, `-` for stdin, or undefined (stdin for scrub/audit). */
  input?: string;
  /** Output path for scrub (`-o`) and init (`-o`). */
  output?: string;
  inPlace: boolean;
  rulesPath?: string;
  noConfig: boolean;
  mode?: RedactMode;
  salt?: string;
  dropContent: boolean;
  report: boolean;
  quiet: boolean;
  json: boolean;
}

/** Thrown on any user error; the CLI maps it to exit code 2. */
export class UsageError extends Error {}

const COMMANDS: readonly Command[] = ["scrub", "audit", "rules", "init"];
const MODES: readonly RedactMode[] = ["mask", "hash", "remove"];

function needsValue(flag: string, value: string | undefined): string {
  if (value === undefined) throw new UsageError(`${flag} requires a value`);
  return value;
}

/** Parse argv (past node + script). Throws UsageError on any mistake. */
export function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: "scrub",
    inPlace: false,
    noConfig: false,
    dropContent: false,
    report: false,
    quiet: false,
    json: false,
  };
  const positionals: string[] = [];
  let commandSet = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    switch (arg) {
      case "--help":
      case "-h":
        return { ...opts, command: "help" };
      case "--version":
      case "-V":
        return { ...opts, command: "version" };
      case "-o":
      case "--out":
        opts.output = needsValue(arg, argv[++i]);
        break;
      case "--in-place":
      case "-i":
        opts.inPlace = true;
        break;
      case "--rules":
        opts.rulesPath = needsValue(arg, argv[++i]);
        break;
      case "--no-config":
        opts.noConfig = true;
        break;
      case "--mode": {
        const value = needsValue(arg, argv[++i]);
        if (!MODES.includes(value as RedactMode)) {
          throw new UsageError(`--mode must be one of ${MODES.join(", ")} (got "${value}")`);
        }
        opts.mode = value as RedactMode;
        break;
      }
      case "--salt":
        opts.salt = needsValue(arg, argv[++i]);
        break;
      case "--drop-content":
        opts.dropContent = true;
        break;
      case "--report":
        opts.report = true;
        break;
      case "--quiet":
      case "-q":
        opts.quiet = true;
        break;
      case "--json":
        opts.json = true;
        break;
      default:
        if (arg.startsWith("-") && arg !== "-") {
          throw new UsageError(`unknown option: ${arg}`);
        }
        if (!commandSet && positionals.length === 0 && COMMANDS.includes(arg as Command)) {
          opts.command = arg as Command;
          commandSet = true;
        } else {
          positionals.push(arg);
        }
    }
  }

  if (positionals.length > 1) {
    throw new UsageError(`unexpected argument: ${positionals[1]}`);
  }
  const positional = positionals[0];

  switch (opts.command) {
    case "scrub":
    case "audit":
      opts.input = positional ?? "-";
      break;
    case "rules":
      if (positional !== undefined) {
        throw new UsageError(`"rules" takes no positional argument (got "${positional}")`);
      }
      break;
    case "init":
      if (positional !== undefined) {
        throw new UsageError(`"init" takes no positional argument; use -o <file>`);
      }
      break;
    default:
      break;
  }

  // Cross-flag validation, per command.
  if (opts.inPlace) {
    if (opts.command !== "scrub") throw new UsageError(`--in-place only applies to scrub`);
    if (opts.output !== undefined) throw new UsageError(`--in-place conflicts with -o`);
    if (opts.input === "-") throw new UsageError(`--in-place needs a file, not stdin`);
  }
  if (opts.output !== undefined && opts.command !== "scrub" && opts.command !== "init") {
    throw new UsageError(`-o only applies to scrub and init`);
  }
  if (opts.json && opts.command !== "audit" && opts.command !== "rules") {
    throw new UsageError(`--json only applies to audit and rules`);
  }
  if (opts.report && opts.command !== "scrub") {
    throw new UsageError(`--report only applies to scrub`);
  }
  if (opts.command === "init") {
    for (const [flag, set] of [
      ["--mode", opts.mode !== undefined],
      ["--salt", opts.salt !== undefined],
      ["--rules", opts.rulesPath !== undefined],
      ["--drop-content", opts.dropContent],
    ] as const) {
      if (set) throw new UsageError(`${flag} does not apply to init`);
    }
  }
  return opts;
}

export const USAGE = `harscrub — redact secrets from HAR files before sharing

Usage:
  harscrub [scrub] [<input.har>|-] [options]   scrub and print to stdout
  harscrub audit  [<input.har>|-] [options]    list what would be redacted
  harscrub rules  [options]                    show the effective rule set
  harscrub init   [-o <file>]                  write a starter harscrub.json

Scrub options:
  -o, --out <file>     write the scrubbed HAR to a file
  -i, --in-place       overwrite the input file
      --drop-content   remove all response bodies
      --report         print a per-rule redaction table to stderr
  -q, --quiet          suppress the stderr summary line

Rule options (scrub, audit, rules):
      --rules <file>   rules file (default: ./harscrub.json if present)
      --no-config      ignore ./harscrub.json
      --mode <m>       mask | hash | remove   (default: mask)
      --salt <text>    salt for hash mode placeholders

Other:
      --json           machine-readable output (audit, rules)
  -h, --help           show this help
  -V, --version        show the version

Exit codes: 0 ok · 1 audit found redactable values · 2 usage or input error
`;
