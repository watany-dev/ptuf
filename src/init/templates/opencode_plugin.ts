// Managed by ptuf. Do not edit manually.
// ptuf-agent: opencode
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__

import { spawn } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

const PTUF_BINARY = __PTUF_BINARY__;
const TIMEOUT_MS = Number(process.env.PTUF_OPENCODE_TIMEOUT_MS ?? "10000");
const MAX_CAPTURE_BYTES = 65536;
const KILL_GRACE_MS = 1000;

type PtufDecision = {
  decision: "allow" | "monitor" | "deny";
  rule_id?: string;
  reason?: string;
};

function readText(stream: NodeJS.ReadableStream, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      if (text.length >= maxBytes) {
        return;
      }
      const remaining = maxBytes - text.length;
      text += chunk.length > remaining ? chunk.slice(0, remaining) : chunk;
    });
    stream.on("error", reject);
    stream.on("end", () => {
      resolve(text);
    });
  });
}

async function runPtufHook(payload: Record<string, unknown>): Promise<PtufDecision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    const proc = spawn(PTUF_BINARY, ["hook", "opencode"], {
      stdio: ["pipe", "pipe", "pipe"],
      signal: controller.signal,
    });

    controller.signal.addEventListener(
      "abort",
      () => {
        killTimer = setTimeout(() => {
          proc.kill("SIGKILL");
        }, KILL_GRACE_MS);
      },
      { once: true },
    );

    proc.stdin.end(JSON.stringify(payload));

    const exited = new Promise<number | null>((resolve, reject) => {
      proc.on("error", reject);
      proc.on("close", (code) => {
        resolve(code);
      });
    });

    const [stdout, stderr, exitCode] = await Promise.all([
      readText(proc.stdout, MAX_CAPTURE_BYTES),
      readText(proc.stderr, MAX_CAPTURE_BYTES),
      exited,
    ]);

    if (exitCode !== 0 && exitCode !== 2) {
      throw new Error(`ptuf hook opencode exited ${exitCode}: ${stderr}`);
    }
    const line = stdout.trim().split("\n").pop() ?? "";
    if (!line) {
      throw new Error("ptuf hook opencode returned empty stdout");
    }
    const decision = JSON.parse(line) as PtufDecision;
    const permitted = decision.decision === "allow" || decision.decision === "monitor";
    if (permitted !== (exitCode === 0)) {
      throw new Error(
        `ptuf hook opencode decision ${decision.decision} is inconsistent with exit ${exitCode}`,
      );
    }
    return decision;
  } finally {
    clearTimeout(timer);
    if (killTimer !== undefined) {
      clearTimeout(killTimer);
    }
  }
}

export const Ptuf: Plugin = async ({ directory, worktree }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const payload = {
        tool_name: input.tool,
        tool_input: output.args ?? {},
        opencode: {
          cwd: directory,
          worktree,
          sessionId: input.sessionID,
          callId: input.callID,
        },
      };

      const result = await runPtufHook(payload);

      if (result.decision === "allow" || result.decision === "monitor") {
        return;
      }
      throw new Error(result.reason ?? "blocked by ptuf");
    },
  };
};
