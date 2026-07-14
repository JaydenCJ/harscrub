// Shared test helpers: a HAR factory, temp dirs with cleanup, and a
// runner for the built CLI. Everything is deterministic — fresh mkdtemp
// directories, fixed fixture values, no network, no clocks.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");

/** A well-known, fake JWT (the classic documentation example token). */
export const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciIsImlhdCI6MTUxNjIzOTAyMn0." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/** Build a minimal valid HAR around the given entries. */
export function makeHar(entries) {
  return {
    log: {
      version: "1.2",
      creator: { name: "test", version: "1.0" },
      entries,
    },
  };
}

/** Build one entry, deep-merging partial request/response overrides. */
export function makeEntry({ request = {}, response = {} } = {}) {
  return {
    startedDateTime: "2026-07-10T09:00:00.000Z",
    time: 10,
    request: {
      method: "GET",
      url: "https://api.example.test/v1/ping",
      httpVersion: "HTTP/2",
      headers: [],
      queryString: [],
      cookies: [],
      headersSize: 100,
      bodySize: 0,
      ...request,
    },
    response: {
      status: 200,
      statusText: "OK",
      httpVersion: "HTTP/2",
      headers: [],
      cookies: [],
      content: { size: 0, mimeType: "text/plain", text: "" },
      redirectURL: "",
      headersSize: 100,
      bodySize: 0,
      ...response,
    },
    cache: {},
    timings: { send: 1, wait: 8, receive: 1 },
  };
}

/** Create a temp dir with the given files; returns { dir, cleanup }. */
export function makeDir(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), "harscrub-test-"));
  for (const [name, content] of Object.entries(files)) {
    const data = typeof content === "string" ? content : JSON.stringify(content, null, 2);
    writeFileSync(join(dir, name), data);
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/**
 * Run the built CLI synchronously. Returns { status, stdout, stderr }.
 * Pass `input` to feed stdin, `cwd` to control config discovery.
 */
export function runCli(args, { input, cwd } = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    input: input ?? "",
    cwd: cwd ?? ROOT,
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
