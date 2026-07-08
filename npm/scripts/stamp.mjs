#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const mainPackage = join(root, "npm/ptuf/package.json");

const platforms = [
  ["@watany-dev/ptuf-cli-darwin-arm64", "cli-darwin-arm64", "aarch64-apple-darwin", "ptuf"],
  ["@watany-dev/ptuf-cli-darwin-x64", "cli-darwin-x64", "x86_64-apple-darwin", "ptuf"],
  ["@watany-dev/ptuf-cli-linux-arm64-gnu", "cli-linux-arm64-gnu", "aarch64-unknown-linux-gnu", "ptuf"],
  ["@watany-dev/ptuf-cli-linux-arm64-musl", "cli-linux-arm64-musl", "aarch64-unknown-linux-musl", "ptuf"],
  ["@watany-dev/ptuf-cli-linux-x64-gnu", "cli-linux-x64-gnu", "x86_64-unknown-linux-gnu", "ptuf"],
  ["@watany-dev/ptuf-cli-linux-x64-musl", "cli-linux-x64-musl", "x86_64-unknown-linux-musl", "ptuf"],
  ["@watany-dev/ptuf-cli-win32-x64", "cli-win32-x64", "x86_64-pc-windows-msvc", "ptuf.exe"]
];

function parseArgs(argv) {
  const args = { artifacts: undefined, version: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--artifacts") {
      i += 1;
      args.artifacts = argv[i];
    } else if (arg === "--version") {
      i += 1;
      args.version = argv[i];
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return args;
}

function packageVersionFromTag(tag) {
  if (!tag) {
    throw new Error("pass --version vX.Y.Z or set GITHUB_REF_NAME");
  }
  return tag.startsWith("v") ? tag.slice(1) : tag;
}

function cargoVersion() {
  const cargoToml = readFileSync(join(root, "Cargo.toml"), "utf8");
  const match = cargoToml.match(/^version = "([^"]+)"$/m);
  if (!match) {
    throw new Error("could not find Cargo.toml package version");
  }
  return match[1];
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function stampVersions(version) {
  const main = readJson(mainPackage);
  main.version = version;
  for (const [name] of platforms) {
    main.optionalDependencies[name] = version;
  }
  writeJson(mainPackage, main);

  for (const [, dir] of platforms) {
    const path = join(root, "npm/platform", dir, "package.json");
    const pkg = readJson(path);
    pkg.version = version;
    writeJson(path, pkg);
  }
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with ${result.status}`);
  }
}

function findArchive(artifacts, target) {
  const extension = target.endsWith("windows-msvc") ? ".zip" : ".tar.gz";
  const archive = join(artifacts, `ptuf-${target}${extension}`);
  if (!existsSync(archive)) {
    throw new Error(`missing release archive: ${archive}`);
  }
  return archive;
}

function findBinary(dir, binaryName) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      const found = findBinary(path, binaryName);
      if (found) {
        return found;
      }
    } else if (basename(path) === binaryName) {
      return path;
    }
  }
  return undefined;
}

function placeBinaries(artifacts) {
  for (const [, dir, target, binaryName] of platforms) {
    const archive = findArchive(resolve(artifacts), target);
    const tmp = mkdtempSync(join(tmpdir(), `ptuf-${target}-`));
    try {
      if (archive.endsWith(".zip")) {
        run("unzip", ["-q", archive, "-d", tmp]);
      } else {
        run("tar", ["-xzf", archive, "-C", tmp]);
      }

      const binary = findBinary(tmp, binaryName);
      if (!binary) {
        throw new Error(`archive ${archive} did not contain ${binaryName}`);
      }

      const binDir = join(root, "npm/platform", dir, "bin");
      mkdirSync(binDir, { recursive: true });
      const dest = join(binDir, binaryName);
      copyFileSync(binary, dest);
      if (binaryName === "ptuf") {
        chmodSync(dest, 0o755);
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
}

const args = parseArgs(process.argv.slice(2));
const version = packageVersionFromTag(args.version ?? process.env.GITHUB_REF_NAME);
const cargo = cargoVersion();
if (version !== cargo) {
  throw new Error(`version mismatch: tag/package ${version} != Cargo.toml ${cargo}`);
}

stampVersions(version);
if (args.artifacts) {
  placeBinaries(args.artifacts);
}
