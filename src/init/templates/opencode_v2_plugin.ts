// Managed by ptuf. Do not edit manually.
// ptuf-agent: opencode-v2
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__

import { spawn } from "node:child_process";
import { Plugin } from "@opencode/plugin";

const PTUF_BINARY = __PTUF_BINARY__;
// __PTUF_SUBPROCESS__

export default Plugin.define({
  id: "ptuf",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", async (event) => {
      const payload = {
        tool_name: event.tool,
        tool_input: (event.input ?? {}) as Record<string, unknown>,
        opencode: {
          cwd: ctx.location.directory,
          sessionId: event.sessionID,
          callId: event.id,
        },
      };

      const result = await runPtufHook(payload);

      if (result.decision === "allow" || result.decision === "monitor") {
        return;
      }
      throw new Error(result.reason ?? "blocked by ptuf");
    });
  },
});
