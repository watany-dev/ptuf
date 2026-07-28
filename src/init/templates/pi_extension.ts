// Managed by ptuf. Do not edit manually.
// ptuf-agent: pi
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__

import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PTUF_BINARY = __PTUF_BINARY__;
const ASK_MODE = process.env.PTUF_PI_ASK_MODE ?? "confirm-if-ui-else-deny";
const TIMEOUT_MS = Number(process.env.PTUF_PI_TIMEOUT_MS ?? "10000");

type PtufDecision = {
  decision: "allow" | "monitor" | "ask" | "deny";
  rule_id?: string;
  reason?: string;
};

function readText(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      text += chunk;
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
  try {
    const proc = spawn(PTUF_BINARY, ["hook", "pi"], {
      stdio: ["pipe", "pipe", "pipe"],
      signal: controller.signal,
    });
    proc.stdin.end(JSON.stringify(payload));

    const exited = new Promise<number | null>((resolve, reject) => {
      proc.on("error", reject);
      proc.on("close", (code) => {
        resolve(code);
      });
    });

    const [stdout, stderr, exitCode] = await Promise.all([
      readText(proc.stdout),
      readText(proc.stderr),
      exited,
    ]);

    if (exitCode !== 0 && exitCode !== 2) {
      throw new Error(`ptuf hook pi exited ${exitCode}: ${stderr}`);
    }
    const line = stdout.trim().split("\n").pop() ?? "";
    if (!line) {
      throw new Error("ptuf hook pi returned empty stdout");
    }
    return JSON.parse(line) as PtufDecision;
  } catch (err) {
    return {
      decision: "deny",
      rule_id: "core.engine.invalid-payload",
      reason: `ptuf hook pi failed: ${String(err)}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

function shouldConfirmAsk(decision: PtufDecision, hasUi: boolean): boolean {
  if (decision.decision !== "ask") {
    return false;
  }
  switch (ASK_MODE) {
    case "always-confirm":
      return true;
    case "always-deny":
      return false;
    case "confirm-if-ui-else-deny":
    default:
      return hasUi;
  }
}

export default function register(pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    const eventInput = (event as { input?: unknown; toolInput?: unknown }).input
      ?? (event as { input?: unknown; toolInput?: unknown }).toolInput
      ?? {};
    const payload = {
      tool_name: event.toolName,
      tool_input: eventInput,
      pi: {
        cwd: ctx.cwd,
        sessionId: ctx.sessionManager.getSessionId(),
      },
    };

    const result = await runPtufHook(payload);

    if (result.decision === "allow" || result.decision === "monitor") {
      return;
    }

    if (result.decision === "ask") {
      if (shouldConfirmAsk(result, ctx.hasUI)) {
        const ok = await ctx.ui.confirm(
          "ptuf requires confirmation",
          result.reason ?? "ptuf requires confirmation for this tool call",
        );
        if (ok) {
          return;
        }
      }
      return { block: true, reason: result.reason ?? "blocked by ptuf ask policy" };
    }

    return {
      block: true,
      reason: result.reason ?? "blocked by ptuf",
    };
  });
}
