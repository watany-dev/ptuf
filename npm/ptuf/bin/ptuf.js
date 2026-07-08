#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");

const packages = {
  "darwin arm64": "@watany-dev/ptuf-cli-darwin-arm64/bin/ptuf",
  "darwin x64": "@watany-dev/ptuf-cli-darwin-x64/bin/ptuf",
  "linux arm64 glibc": "@watany-dev/ptuf-cli-linux-arm64-gnu/bin/ptuf",
  "linux arm64 musl": "@watany-dev/ptuf-cli-linux-arm64-musl/bin/ptuf",
  "linux x64 glibc": "@watany-dev/ptuf-cli-linux-x64-gnu/bin/ptuf",
  "linux x64 musl": "@watany-dev/ptuf-cli-linux-x64-musl/bin/ptuf",
  "win32 x64": "@watany-dev/ptuf-cli-win32-x64/bin/ptuf.exe"
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

function packageKey() {
  const parts = [process.platform, process.arch];
  const linuxLibc = libc();
  if (linuxLibc) {
    parts.push(linuxLibc);
  }
  return parts.join(" ");
}

function resolveBinary() {
  if (process.env.PTUF_BINARY_PATH) {
    return process.env.PTUF_BINARY_PATH;
  }

  const packagePath = packages[packageKey()];
  if (!packagePath) {
    return undefined;
  }

  try {
    return require.resolve(packagePath);
  } catch {
    return undefined;
  }
}

const binary = resolveBinary();
if (!binary) {
  console.error(
    "ptuf: unsupported platform or missing optional native package for " +
      `${process.platform}/${process.arch}` +
      (libc() ? `/${libc()}` : "")
  );
  console.error(
    "Supported npm platforms: darwin-arm64, darwin-x64, linux-arm64-gnu, " +
      "linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64."
  );
  console.error("Alternative install methods: https://github.com/watany-dev/ptuf/blob/main/docs/install.md");
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`ptuf: failed to launch ${binary}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status === null ? 1 : result.status);
