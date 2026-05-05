---
name: task-done
description: タスク完了時に simplify と update-docs を順に実行し、最後に /compact のリマインドを出す。Stop hook の block reason から起動されるか、user が「タスク完了」「/task-done」と言ったときに発動する。
---

# task-done スキル

ptuf の編集タスクが終わるたびに毎回手で叩いていた `/simplify` `/update-docs` `/compact` の連鎖を半自動化するためのまとめスキル。Stop hook (`.claude/hooks/stop-task-done.sh`) が `decision: "block"` で呼び出すか、user が直接起動する。

## 手順

1. **simplify を実行**: `Skill` ツールで `simplify` を呼び出し、変更コードのレビュー → 再利用・品質・効率性の修正を完了させる。
2. **update-docs を実行**: `Skill` ツールで `update-docs` を呼び出し、`src/` の変更を `README.md` / `docs/design/` / `CLAUDE.md` に反映させる。
3. **`make check` を流す**: simplify / update-docs が触ったファイルがある場合、`make check` でフォーマット・clippy・test・doc・cargo-deny を確認する (`CLAUDE.md` の必須チェック)。
4. **完了マーカーを書く**:
   - 直前の Stop hook の block reason に絶対パス (例: `/tmp/ptuf-task-done-<session_id>`) が埋め込まれているのでそれを `touch` する。
   - reason から取得できない (user が直接 `/task-done` を叩いた等) 場合は `touch /tmp/ptuf-task-done-default` をフォールバックとして実行する。
5. **user に compact を促す**: 「task-done 完了。`/compact` で context を圧縮してください。」と短く出力する。

## 注意

- **手順 4 (マーカー touch) を必ず実行**すること。書き忘れると次の Stop hook 発火で再ブロックされ、無限ループ気味になる。
- git-check hook が同時に「commit&push してください」と言っている場合、**task-done を全て終えてから** commit してください。simplify / update-docs が docs を変更している可能性があるため。
- simplify / update-docs それ自体が「変更なし」と報告した場合でも手順 4 と 5 は省略しない。
