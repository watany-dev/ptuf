#!/usr/bin/env python3
"""Exercise installed OpenCode hosts with a local model and real ptuf plugins."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Model(BaseHTTPRequestHandler):
    """Only the LLM response is a fixture; host loading and tools are real."""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append({"path": self.path, "body": request})
        tools = [t["function"]["name"] for t in request.get("tools", [])]
        tool = self.server.native_tool
        finished = any(m["role"] == "tool" for m in request.get("messages", []))
        if tool in tools and not finished:
            delta = {
                "role": "assistant",
                "tool_calls": [{
                    "index": 0, "id": "call_ptuf_fixture", "type": "function",
                    "function": {"name": tool, "arguments": json.dumps({
                        "command": self.server.command,
                        "description": "ptuf host integration fixture", "timeout": 10000,
                    })},
                }],
            }
            reason = "tool_calls"
        else:
            delta = {"role": "assistant", "content": "Fixture complete."}
            reason = "stop"
        base = {
            "id": "chatcmpl-ptuf", "object": "chat.completion.chunk",
            "created": int(time.time()), "model": "fixture",
        }
        chunks = [
            dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
            dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": reason}],
                 usage={"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}),
        ]
        body = ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
                + "data: [DONE]\n\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def execute(args, cwd, env, timeout=90):
    with subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise
        return proc.returncode, out, err


def check_host(root, generation, binary, ptuf, server):
    base = root / generation
    repo = base / "project"
    repo.mkdir(parents=True)
    env = os.environ.copy()
    for name, directory in [("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                            ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state"),
                            ("XDG_CACHE_HOME", "cache")]:
        target = base / directory
        target.mkdir()
        env[name] = str(target)
    # Both hosts consult PWD when choosing the session location.
    env.update(PWD=str(repo), OPENCODE_DISABLE_MODELS_FETCH="true",
               OPENCODE_DISABLE_AUTOUPDATE="true", OPENCODE_DISABLE_SHARE="true")
    env["NO_PROXY"] = env.get("NO_PROXY", "") + ",127.0.0.1,localhost"

    def setup(args):
        code, out, err = execute(args, repo, env)
        assert code == 0, (args, code, out, err)
        return out.strip()

    version = setup([binary, "--version"])
    assert version.removeprefix("opencode ").removeprefix("v").startswith(generation[1:] + "."), version
    setup(["git", "init", "--initial-branch=main"])
    (repo / "sentinel.txt").write_text("committed\n")
    setup(["git", "add", "sentinel.txt"])
    setup(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
           "commit", "-m", "fixture"])
    (repo / "sentinel.txt").write_text("dirty sentinel\n")
    audit = base / "audit.jsonl"
    (repo / ".ptuf.yaml").write_text(
        f"version: 1\naudit:\n  enabled: true\n  includeAllowed: true\n  path: {json.dumps(str(audit))}\n"
    )
    setup([ptuf, "init", "opencode-" + generation, "--no-verify"])
    plugin = base / "config/opencode/plugins/ptuf.ts"
    installed = plugin.read_bytes()
    setup([ptuf, "init", "--no-verify"])
    assert plugin.read_bytes() == installed, "auto-init changed the managed generation"
    (repo / "opencode.json").write_text(json.dumps({
        "model": "fixture/fixture", "small_model": "fixture/fixture", "permission": "allow",
        "provider": {"fixture": {
            "npm": "@ai-sdk/openai-compatible", "name": "Local fixture",
            "options": {"baseURL": f"http://127.0.0.1:{server.server_port}/v1",
                        "apiKey": "fixture-local-only"},
            "models": {"fixture": {"name": "fixture", "tool_call": True,
                                   "limit": {"context": 128000, "output": 4096}}},
        }},
    }))
    server.native_tool = "bash" if generation == "v1" else "shell"
    for case, command in [("allow", "printf 'safe executed' > allowed.txt"),
                          ("deny", "git reset --hard HEAD")]:
        server.command, server.requests = command, []
        args = [binary, "run", "--format", "json", "--model", "fixture/fixture",
                "--title", "ptuf host fixture", "--auto"]
        if generation == "v2":
            args.append("--standalone")
        code, out, err = execute(args + ["Run the fixture tool once."], repo, env)
        (base / f"{case}.stdout").write_text(out)
        (base / f"{case}.stderr").write_text(err)
        (base / f"{case}.requests.json").write_text(json.dumps(server.requests, indent=2))
        assert code == 0, (generation, case, code, out, err)
        calls = [json.loads(line)["part"] for line in out.splitlines()
                 if json.loads(line).get("type") == "tool_use"]
        assert len(calls) == 1, (generation, case, calls)
        assert calls[0]["tool"] == server.native_tool, calls
        state = calls[0]["state"]
        assert state["input"]["command"] == command, state
        if case == "allow":
            assert state["status"] == "completed", state
            assert (repo / "allowed.txt").read_text() == "safe executed"
        else:
            assert state["status"] == "error", state
            assert "Blocked by ptuf rule core.git.reset-hard" in state["error"], state
            assert (repo / "sentinel.txt").read_text() == "dirty sentinel\n"
        print(f"{version}: {server.native_tool} {case}: passed", flush=True)
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(r["tool"] == "Bash" and r["decision"] == "allow" for r in records), records
    assert any(r.get("ruleId") == "core.git.reset-hard" and r["decision"] in ("ask", "deny")
               for r in records), records
    return {"generation": generation, "version": version, "allow": "passed", "deny": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1", required=True, type=Path)
    parser.add_argument("--v2", required=True, type=Path)
    parser.add_argument("--ptuf", default=Path("target/debug/ptuf"), type=Path)
    parser.add_argument("--output", type=Path, help="Parent for a new isolated artifact directory")
    args = parser.parse_args()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="ptuf-opencode-hosts-", dir=args.output)).resolve()
    print(f"Artifacts: {root}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        results = [check_host(root, generation, str(binary.resolve()), str(args.ptuf.resolve()), server)
                   for generation, binary in [("v1", args.v1), ("v2", args.v2)]]
        (root / "results.json").write_text(json.dumps(results, indent=2))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
