# Codex skills

From the repository root, invoke `$kick #123 #456` in Codex. The supplied issues
are handled in one PR. `$wrapup`, `$ponytail-review`, `$cleanup-comments`, and
`$update-docs` can also be invoked individually.

The workflow skills listed above are independent copies of the Claude skills.
Only the skill invocation notation changes from `/name` to `$name`; the workflow
and policies follow the original definitions. Edit `.agents/skills/` for Codex.
Claude Code continues to use its original files under `.claude/skills/`.

Dependencies:

```text
kick
├── wrapup
│   ├── ponytail-review
│   └── cleanup-comments
└── update-docs (when documentation needs synchronization)
```

`/code-review` has a self-review fallback in `wrapup`; no Claude plugin is
required.

When a skill calls another skill, read its `.agents/skills/<name>/SKILL.md` and
follow those steps in the current task.

Start a new Codex session in this repository if it has not discovered the skills.
