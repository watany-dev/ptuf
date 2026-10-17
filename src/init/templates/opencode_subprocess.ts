// Shared by both host adapters at generation time; installed plugins stay standalone.
const HOOK_TOKEN = "__PTUF_HOOK_TOKEN__";
const configuredTimeout = Number(process.env.PTUF_OPENCODE_TIMEOUT_MS ?? "10000");
const TIMEOUT_MS = Number.isFinite(configuredTimeout) && configuredTimeout > 0
  ? configuredTimeout : 10000;
const MAX_CAPTURE_BYTES = 65536;
const KILL_GRACE_MS = 1000;

type PtufDecision = {
  decision: "allow" | "monitor" | "deny";
  rule_id?: string;
  reason?: string;
};

function readText(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = "";
    let bytes = 0;
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_CAPTURE_BYTES) {
        reject(new Error(`ptuf hook ${HOOK_TOKEN} output exceeds limit`));
        return;
      }
      text += chunk;
    });
    stream.on("error", reject);
    stream.on("end", () => resolve(text));
  });
}

async function runPtufHook(payload: Record<string, unknown>): Promise<PtufDecision> {
  const input = JSON.stringify(payload);
  const proc = spawn(PTUF_BINARY, ["hook", "__PTUF_HOOK_TOKEN__"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let timedOut = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill("SIGTERM");
    // Keep the escalation alive until close; an AbortError would otherwise
    // reject early and let finally cancel SIGKILL for an unresponsive child.
    killTimer = setTimeout(() => proc.kill("SIGKILL"), KILL_GRACE_MS);
  }, TIMEOUT_MS);
  try {
    const exited = new Promise<number | null>((resolve, reject) => {
      proc.on("error", reject);
      proc.stdin.on("error", reject);
      proc.on("close", resolve);
    });
    const stdout = readText(proc.stdout);
    const stderr = readText(proc.stderr);
    proc.stdin.end(input);
    const [out, err, exitCode] = await Promise.all([stdout, stderr, exited]);
    if (timedOut) {
      throw new Error(`ptuf hook ${HOOK_TOKEN} timed out`);
    }
    if (exitCode !== 0 && exitCode !== 2) {
      throw new Error(`ptuf hook ${HOOK_TOKEN} exited ${exitCode}: ${err}`);
    }
    const line = out.trim().split("\n").pop() ?? "";
    if (!line) {
      throw new Error(`ptuf hook ${HOOK_TOKEN} returned empty stdout`);
    }
    const decision = JSON.parse(line) as PtufDecision;
    if (!decision || !["allow", "monitor", "deny"].includes(decision.decision)) {
      throw new Error(`ptuf hook ${HOOK_TOKEN} returned an invalid decision`);
    }
    const permitted = decision.decision === "allow" || decision.decision === "monitor";
    if (permitted !== (exitCode === 0)) {
      throw new Error(
        `ptuf hook ${HOOK_TOKEN} decision ${decision.decision} is inconsistent with exit ${exitCode}`,
      );
    }
    return decision;
  } catch (error) {
    proc.kill("SIGKILL");
    throw error;
  } finally {
    clearTimeout(timer);
    if (killTimer !== undefined) clearTimeout(killTimer);
  }
}
