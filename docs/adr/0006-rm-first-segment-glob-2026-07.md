# ADR 0006 — rm 第1セグメント glob 展開前 bypass (2026-07)

## Status

Accepted (2026-07-08).

## Context

ADR 0002 Known limitations C3 として受容されていた bypass。`rm -rf /e*` は
shell の glob 展開で `/etc` にマッチしうるが、`destructive_rm::is_destructive_target`
は `normalize_rm_target` 後に `/` / `/*` / HOME / `SYSTEM_ROOTS` 前置一致のみを
判定し、第1パスセグメントに glob メタ (`*`, `?`, `[`) を含む絶対パスを取り逃していた。
`tests/bypass/corpus.jsonl` にも未 pin だった (Issue #155)。

## Decision

**絶対パス (`/` 始まり) で、第1パスセグメントに glob メタを含むものを悲観的に
destructive 扱いする。**

- `first_segment_has_glob(path)` を追加: `strip_prefix('/')` → 最初の `/` 手前
  セグメントに `*?[` を含むか判定
- `is_destructive_target` の `..` 判定直後、`normalize_rm_target` 後に呼び出す
- 第2セグメント以降の glob (`/tmp/*`, `/home/u/*`) は既存 `SYSTEM_ROOTS` 前置
  判定に委ね、正当ワークフローを allow のまま維持する

### 判定の想定

| 結果 | 例 |
| --- | --- |
| deny 追加 | `rm -rf /e*`, `/et*`, `/u*`, `/t*`, `/[a-z]*` |
| allow 維持 | `rm -rf /tmp/*`, `/home/user/*`, `./build/*`, `*.txt`, `/etcd` |

## Consequences

### Positive

- `rm -rf /e*` 等、glob 展開前に `/etc` 等へマッチしうる形が Critical Deny になる。
- 第1セグメント限定のため `/tmp/*` 等の既存 allow ワークフローは維持される。
- ADR 0002 C3 が解消され、bypass corpus に pin される。

### Negative

- `rm -rf /usr*` 等、第1セグメント prefix glob の正当用途 (存在しないパスの
  一括削除等) も deny になる。hard_deny rule のため allowlist 不可 — 明示的な
  パス指定 (`rm -rf /usr/local/myapp`) を推奨する設計トレードオフ。

### Known limitations (継続)

- ADR 0002 / 0003 の B1/B2/B5/C2 (Unicode homoglyph / symlink / cmdsubst /
  変数 head) は据え置き。
- shell 実行時 glob 展開のシミュレーションは行わない (parser 限界)。

## Implementation map

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| 判定 | `src/rules/destructive_rm.rs` | `first_segment_has_glob`, `is_destructive_target` 拡張 |
| Tests | `src/rules/destructive_rm.rs` mod tests | deny/allow 表 + PBT target 追加 |
| Corpus | `tests/bypass/corpus.jsonl` | `destructive-rm-first-segment-glob-etc` |
| Doc | `docs/design/policy-packs.md`, ADR 0002/0003 | C3 解消追従 |
