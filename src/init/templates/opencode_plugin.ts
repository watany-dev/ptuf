// Managed by ptuf. Do not edit manually.
// ptuf-agent: opencode
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__

import { spawn } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

const PTUF_BINARY = __PTUF_BINARY__;
// __PTUF_SUBPROCESS__

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
