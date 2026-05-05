#!/bin/bash
# Stop hook: Claude が応答を終了する直前に発火し、task-done skill が
# 実行済みかをマーカーファイルで検査する。未実行なら decision:"block" で
# Claude に task-done 起動を促す。
#
# 設計上の注意:
#   - `stop_hook_active` は意図的に見ない。user-level git-check hook が
#     先に block して再帰した場合に短絡してしまい、task-done が起動しない罠
#     を回避するため、独自マーカーで状態管理する。
#   - Q&A 応答での誤発火を避けるため、transcript JSONL の末尾 user turn
#     以降に Edit/Write/MultiEdit/NotebookEdit の tool_use があったかで判定。
set -euo pipefail

# jq 必須。無い環境ではフェイルセーフで素通り。
command -v jq >/dev/null 2>&1 || exit 0

input=$(cat)

# git repo 外なら何もしない (CLAUDE_PROJECT_DIR が想定と違うケース)
git rev-parse --git-dir >/dev/null 2>&1 || exit 0

session_id=$(echo "$input" | jq -r '.session_id // "default"')
transcript=$(echo "$input" | jq -r '.transcript_path // ""')
marker="${TMPDIR:-/tmp}/ptuf-task-done-$session_id"

# 編集系 tool_use 名のリスト。SKILL.md の手順で「編集」と扱うものと揃える。
edit_tools_re='"name":"(Edit|Write|MultiEdit|NotebookEdit)"'

# マーカー存在 = task-done 実行済 → 許可。次の user turn で再ブロックする
# ためにマーカーを削除する。
if [ -f "$marker" ]; then
  rm -f "$marker"
  exit 0
fi

# Q&A ターン heuristic: transcript を tac で逆順に流し、最後の user turn
# と編集系 tool_use のうち先に現れた方を `grep -m1` で検出する。
# 編集系が先 (= 元の順序では user turn の後) → block。
# user turn が先 (= 編集系が無かった) → skip。
# transcript が読めない / 空なら安全側に倒して block する。
should_block=true
if [ -n "$transcript" ] && [ -r "$transcript" ]; then
  first_match=$(tac "$transcript" 2>/dev/null \
    | grep -m1 -E "(\"type\":\"user\"|$edit_tools_re)" || true)
  case "$first_match" in
    *'"type":"user"'*) should_block=false ;;
  esac
fi

if [ "$should_block" = false ]; then
  exit 0
fi

# block + 指示。skill が拾えるよう reason に marker 絶対パスを埋め込む。
jq -n --arg marker "$marker" '{
  decision: "block",
  reason: ("終了前に task-done skill を実行してください。Skill ツールで `task-done` を呼び出すと simplify と update-docs が順に走り、最後に `/compact` のリマインドが出ます。完了したら最後に `touch " + $marker + "` を必ず実行してください (このマーカーが無いと無限にブロックされます)。git-check hook も同時に block している場合は task-done を先に終えてから commit&push してください。")
}'
