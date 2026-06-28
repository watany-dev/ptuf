// Managed by ptuf. Do not edit manually.
// ptuf-agent: pi
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const PTUF_BINARY = "__PTUF_BINARY__";
const ASK_MODE = process.env.PTUF_PI_ASK_MODE ?? "confirm-if-ui-else-deny";
const TIMEOUT_MS = Number(process.env.PTUF_PI_TIMEOUT_MS ?? "10000");

type PtufDecision = {
  decision: "allow" | "monitor" | "ask" | "deny";
  rule_id?: string;
  reason?: string;
};

async function runPtufHook(payload: Record<string, unknown>): Promise<PtufDecision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const proc = Bun.spawn({
      cmd: [PTUF_BINARY, "hook", "pi"],
      stdin: JSON.stringify(payload),
      stdout: "pipe",
      stderr: "pipe",
      signal: controller.signal,
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
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
    const payload = {
      tool_name: event.toolName,
      tool_input: event.toolInput ?? {},
      pi: {
        cwd: ctx.cwd,
        sessionId: ctx.sessionId,
      },
    };

    const result = await runPtufHook(payload);

    if (result.decision === "allow" || result.decision === "monitor") {
      return;
    }

    if (result.decision === "ask") {
      const hasUi = Boolean((ctx as { ui?: unknown }).ui);
      if (shouldConfirmAsk(result, hasUi)) {
        const ok = await ctx.confirm?.(
          result.reason ?? "ptuf requires confirmation for this tool call",
        );
        if (ok) {
          return;
        }
      }
      return { block: true, message: result.reason ?? "blocked by ptuf ask policy" };
    }

    return {
      block: true,
      message: result.reason ?? "blocked by ptuf",
    };
  });
}
