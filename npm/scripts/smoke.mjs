#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const packages = {
  "darwin arm64": ["@ptuf/cli-darwin-arm64", "cli-darwin-arm64", "bin/ptuf"],
  "darwin x64": ["@ptuf/cli-darwin-x64", "cli-darwin-x64", "bin/ptuf"],
  "linux arm64 glibc": ["@ptuf/cli-linux-arm64-gnu", "cli-linux-arm64-gnu", "bin/ptuf"],
  "linux arm64 musl": ["@ptuf/cli-linux-arm64-musl", "cli-linux-arm64-musl", "bin/ptuf"],
  "linux x64 glibc": ["@ptuf/cli-linux-x64-gnu", "cli-linux-x64-gnu", "bin/ptuf"],
  "linux x64 musl": ["@ptuf/cli-linux-x64-musl", "cli-linux-x64-musl", "bin/ptuf"],
  "win32 x64": ["@ptuf/cli-win32-x64", "cli-win32-x64", "bin/ptuf.exe"]
};

function libc() {
  if (process.platform !== "linux") {
    return "";
  }

  const report = process.report && process.report.getReport
    ? process.report.getReport()
    : undefined;
  return report && report.header && report.header.glibcVersionRuntime
    ? "glibc"
    : "musl";
}

function hostKey() {
  const parts = [process.platform, process.arch];
  const linuxLibc = libc();
  if (linuxLibc) {
    parts.push(linuxLibc);
  }
  return parts.join(" ");
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with ${result.status}\n${result.stderr}`);
  }
  return result;
}

function capture(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function pack(packageDir, cwd) {
  const result = run("npm", ["pack", "--ignore-scripts", packageDir, "--cache", join(cwd, ".npm-cache")], { cwd });
  return join(cwd, result.stdout.trim().split(/\r?\n/).at(-1));
}

function packageVersion() {
  return JSON.parse(readFileSync(join(root, "npm/ptuf/package.json"), "utf8")).version;
}

const platform = packages[hostKey()];
if (!platform) {
  throw new Error(`unsupported smoke platform: ${hostKey()}`);
}

const [platformName, platformDir, binaryRel] = platform;
const work = mkdtempSync(join(tmpdir(), "ptuf-npm-smoke-"));
const platformTarball = pack(join(root, "npm/platform", platformDir), work);
const mainTarball = pack(join(root, "npm/ptuf"), work);

writeFileSync(
  join(work, "package.json"),
  `${JSON.stringify({
    private: true,
    dependencies: {
      ptuf: `file:${mainTarball}`,
      [platformName]: `file:${platformTarball}`
    }
  }, null, 2)}\n`
);

run("npm", ["install", "--ignore-scripts", "--cache", join(work, ".npm-cache")], { cwd: work });

const bin = process.platform === "win32"
  ? join(work, "node_modules/.bin/ptuf.cmd")
  : join(work, "node_modules/.bin/ptuf");
const native = join(work, "node_modules", ...platformName.split("/"), binaryRel);
const expectedVersion = packageVersion();

const shimVersion = run(bin, ["--version"], { cwd: work });
if (!shimVersion.stdout.includes(expectedVersion)) {
  throw new Error(`shim --version did not contain ${expectedVersion}: ${shimVersion.stdout}`);
}

const nativeDecision = capture(native, ["check", "--tool", "Bash", "rm -rf /"], { cwd: work });
const shimDecision = capture(bin, ["check", "--tool", "Bash", "rm -rf /"], { cwd: work });
if (
  nativeDecision.status !== shimDecision.status ||
  nativeDecision.stdout !== shimDecision.stdout ||
  nativeDecision.stderr !== shimDecision.stderr
) {
  throw new Error("shim output differed from native binary");
}

const initDryRun = run(bin, ["init", "--dry-run", "--json"], { cwd: work });
if (initDryRun.stdout.includes("ptuf.js")) {
  throw new Error("init dry-run wrote the JavaScript shim path");
}
