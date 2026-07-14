/**
 * Minimal ambient declarations for the handful of Node.js built-ins this
 * project uses. Declaring them in-repo keeps `typescript` the only
 * devDependency (no `@types/node`); the surface below is intentionally
 * restricted to exactly what `src/` calls, so a typo against a real Node
 * API still fails to compile.
 */

declare module "node:fs" {
  /** Reading fd 0 (stdin) is the `readFileSync(0, "utf8")` overload. */
  export function readFileSync(path: string | number, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string): void;
  export function existsSync(path: string): boolean;
}

declare module "node:path" {
  export function resolve(...parts: string[]): string;
}

declare module "node:crypto" {
  interface Hash {
    update(data: string): Hash;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: "sha256"): Hash;
}

interface MinimalBuffer {
  toString(encoding: "utf8" | "base64"): string;
  readonly length: number;
}

declare var Buffer: {
  from(data: string, encoding: "utf8" | "base64"): MinimalBuffer;
  byteLength(data: string, encoding?: "utf8"): number;
};

declare var process: {
  argv: string[];
  exitCode: number | undefined;
  exit(code?: number): never;
  cwd(): string;
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
  env: Record<string, string | undefined>;
};
