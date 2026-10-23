# security-audit の導入情報

Cloudflare 公式の、コードベースを対象とするセキュリティ監査スキル。
Cloudflare のアカウント設定を監査する API ツールではない。

- 配布元: https://github.com/cloudflare/security-audit-skill
- 導入コミット: `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
- 導入日: 2026-10-18 (watany-dev/chokkin)。ptuf へは 2026-10-23 に chokkin の
  導入物を同じコミットのまま複製した。
- ライセンス: MIT。原文は同梱の `LICENSE`。
- `skills/security-audit/` の全20ファイルを収録。監査手順と検証コードは変更なし。
- ローカル差分は `SKILL.md` の `disable-model-invocation: true` の追加。
- このファイル、`LICENSE`、`agents/openai.yaml` は導入時に追加。

## 配置

このリポジトリを開いたときに利用するプロジェクト単位の導入。

| ツール | 読込先 |
| --- | --- |
| Claude Code | `.claude/skills/security-audit/SKILL.md` |
| Codex | `.codex/skills/security-audit/SKILL.md` |

実体は `.claude/skills/security-audit/`。
既存の `.codex/skills -> ../.claude/skills` で Codex も同じ実体を参照する。

## 使い方

両 CLI とも明示的な呼出し専用。通常のレビューやセキュリティ相談からは
自動選択しない。

| ツール | 自動呼出しを無効にする設定 |
| --- | --- |
| Claude Code | `SKILL.md` の `disable-model-invocation: true` |
| Codex | `agents/openai.yaml` の `policy.allow_implicit_invocation: false` |

リポジトリを開いて、Claude Code では次を入力する。

```text
/security-audit このコードベースをセキュリティ監査して
```

Codex では次を入力する。

```text
$security-audit このコードベースをセキュリティ監査して
```

局所的な相談なら、呼出しコマンドに「src/ の入力処理をセキュリティレビュー
して」と続ける。通常の相談・部分レビューと、
レポートを生成する全工程の監査は、公式スキルの動作モードに従う。
一覧に表示されない場合は CLI のセッションを再起動する。

同梱の検証スクリプトには Node.js が必要。全工程の監査にはサブエージェント
対応も必要で、対象コードの実行には公式スキルの隔離条件が適用される。
監査結果の保存先は原則リポジトリ外。クラウド環境では、たとえば
`/workspace/scratch/security-audits/ptuf/run-1` のような新しい書込可能な
ディレクトリを依頼時に指定できる。

## 検証・更新

同梱の公式テストはリポジトリルートで実行できる。

```sh
node --test .claude/skills/security-audit/validate-findings.test.cjs .claude/skills/security-audit/validate-coverage-ledger.test.cjs
```

chokkin への導入時は Node.js v24.19.0 で公式テスト65件すべて成功し、
Codex CLI の `skills/list` で `security-audit` が `scope: repo`、`enabled: true`
で認識されること、自動呼出しの無効化が効くことを確認した。ptuf への複製時は
Node.js v22.22.0 で同じ65件の成功を確認した。

更新時は配布元の新コミットを取得し、差分を確認してから
`skills/security-audit/` の全ファイルと `LICENSE` を置き換える。
`SKILL.md` の `disable-model-invocation: true` と `agents/openai.yaml` の
`policy.allow_implicit_invocation: false` は更新後も維持する。
削除された公式ファイルも反映し、このファイルのコミットと日付を更新する。
リンク先が共通なので両 CLI に同じ更新が適用される。
