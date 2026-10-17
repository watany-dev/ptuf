// Node 24 executes the installed TypeScript without a transpiler dependency.
// The v2 SDK shim checks registration, not the implementation of a real host.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

const binary = resolve(process.env.PTUF_TEST_BINARY ?? "target/debug/ptuf");

for (const generation of ["opencode-v1", "opencode-v2"]) {
  test(`${generation}: installed callback enforces the subprocess boundary`, { timeout: 20000 }, async (t) => {
    const root = await mkdtemp(join(tmpdir(), "ptuf-plugin-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const savedEnv = { ...process.env };
    t.after(() => { process.env = savedEnv; });
    const config = join(root, "config");
    process.env.HOME = root;
    process.env.XDG_CONFIG_HOME = config;
    process.env.PTUF_OPENCODE_TIMEOUT_MS = "500";
    const installed = spawnSync(binary, ["init", generation, "--no-verify"], {
      cwd: root, encoding: "utf8", timeout: 10000,
    });
    assert.equal(installed.status, 0, installed.stderr);
    const plugin = join(config, "opencode/plugins/ptuf.ts");
    const original = await readFile(plugin, "utf8");
    await writeFile(join(root, "package.json"), '{"type":"module"}');
    const sdk = join(root, "node_modules/@opencode/plugin");
    await mkdir(sdk, { recursive: true });
    await writeFile(join(sdk, "package.json"), '{"type":"module","exports":"./index.js"}');
    await writeFile(join(sdk, "index.js"), `
      export const Plugin = { define(value) {
        if (value.id !== "ptuf" || typeof value.setup !== "function") throw Error("invalid plugin definition");
        return value;
      }};
    `);
    // This fake executable accepts real stdin and emits hostile CLI responses.
    const fake = join(root, 'fake ptuf " executable');
    const capture = join(root, "capture.json");
    const pidFile = join(root, "child.pid");
    process.env.PTUF_TEST_CAPTURE = capture;
    process.env.PTUF_TEST_PID = pidFile;
    await writeFile(fake, `#!${process.execPath}
      const fs = require("node:fs");
      fs.writeFileSync(process.env.PTUF_TEST_PID, String(process.pid));
      let input = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", chunk => input += chunk);
      process.stdin.on("end", () => {
        fs.writeFileSync(process.env.PTUF_TEST_CAPTURE, JSON.stringify({argv:process.argv.slice(2), input:JSON.parse(input)}));
        const mode = process.env.PTUF_TEST_MODE;
        if (mode === "timeout") { process.on("SIGTERM", () => {}); setInterval(() => {}, 1000); return; }
        if (mode === "overflow") { process.stdout.write("x".repeat(70000)); return; }
        const responses = {
          allow: ['{"decision":"allow"}', 0], monitor: ['{"decision":"monitor"}', 0],
          deny: ['{"decision":"deny","reason":"fixture denial"}', 2],
          invalid: ['{broken', 0], empty: ['', 0], unknown: ['{"decision":"ask"}', 2],
          null: ['null', 0], mismatchAllow: ['{"decision":"allow"}', 2],
          mismatchDeny: ['{"decision":"deny"}', 0], failure: ['{"decision":"allow"}', 1],
        };
        const [body, code] = responses[mode];
        process.stdout.write(body);
        process.exitCode = code;
      });
    `, { mode: 0o700 });
    // A .cjs extension makes the fixture executable CommonJS under type:module.
    const executable = `${fake}.cjs`;
    await writeFile(executable, await readFile(fake), { mode: 0o700 });
    let sequence = 0;
    async function load(executablePath) {
      const file = join(dirname(plugin), `case-${sequence++}.ts`);
      const source = executablePath === undefined ? original : original.replace(
        /^const PTUF_BINARY = .*;$/m, () => `const PTUF_BINARY = ${JSON.stringify(executablePath)};`,
      );
      await writeFile(file, source);
      const module = await import(pathToFileURL(file).href);
      if (generation === "opencode-v1") {
        const hooks = await module.Ptuf({ directory: root, worktree: root });
        assert.equal(typeof hooks["tool.execute.before"], "function");
        return (command) => hooks["tool.execute.before"](
          { tool: "bash", sessionID: "session", callID: "call" }, { args: { command } },
        );
      }
      let callback;
      await module.default.setup({
        location: { directory: root },
        tool: { async hook(name, fn) {
          assert.equal(name, "execute.before");
          assert.equal(callback, undefined, "register only one callback");
          callback = fn;
        } },
      });
      assert.equal(typeof callback, "function");
      return (command) => callback({ tool: "bash", input: { command }, sessionID: "session", id: "call" });
    }
    await t.test("real CLI permits safe commands and blocks dangerous commands", async () => {
      const callback = await load();
      await callback("ls");
      await assert.rejects(callback("rm -rf /"), /destructive|root|filesystem/i);
    });
    for (const [mode, expected] of [
      ["allow", null], ["monitor", null], ["deny", /fixture denial/],
      ["invalid", /JSON|property/i], ["empty", /empty stdout/], ["unknown", /invalid decision/],
      ["null", /invalid decision/], ["mismatchAllow", /inconsistent/], ["mismatchDeny", /inconsistent/],
      ["failure", /exited 1/], ["overflow", /exceeds limit/], ["timeout", /timed out/],
    ]) {
      await t.test(mode, async () => {
        process.env.PTUF_TEST_MODE = mode;
        const callback = await load(executable);
        if (expected) await assert.rejects(callback("ls"), expected);
        else await callback("ls");
        const captured = JSON.parse(await readFile(capture, "utf8"));
        assert.deepEqual(captured.argv, ["hook", generation]);
        assert.equal(captured.input.tool_name, "bash");
        assert.deepEqual(captured.input.tool_input, { command: "ls" });
        assert.equal(captured.input.opencode.cwd, root);
        assert.equal(captured.input.opencode.sessionId, "session");
        assert.equal(captured.input.opencode.callId, "call");
        if (mode === "timeout") {
          const pid = Number(await readFile(pidFile, "utf8"));
          assert.throws(() => process.kill(pid, 0), { code: "ESRCH" }, "reap child that ignores SIGTERM");
        }
      });
    }
    await t.test("spawn failure rejects without an unhandled stdin error", async () => {
      const callback = await load(join(root, "missing-executable"));
      await assert.rejects(callback("ls"), /ENOENT/);
    });
  });
}
