# ptuf 利用者獲得戦略 (Adoption Strategy)

最終更新: 2026-06-10。3ヶ月ゴール = **実利用者の獲得**
(release download の継続増加、外部ユーザからの issue / 質問の発生)。
市場優先度は **日本ファースト → グローバル展開**。

## 1. 現状診断

### 1.1 数字 (2026-06-10 時点)

| 指標 | 値 |
| --- | --- |
| GitHub stars / forks | 1 / 0 |
| 外部ユーザからの issue / Discussion | 0 件 (既存 issue は全て author 起票) |
| v0.3.0 release downloads | installer.sh 11 / x86_64-linux 15 / その他ほぼ 0 |
| 公開からの経過 | 約 5 週間 (2026-05-03 公開) |

### 1.2 構造的な問題

プロダクト品質と配布努力が極端に非対称になっている。

- **作り込みは十分**: 6 ホスト対応、fail-closed、監査ログ、plugin DSL、
  95% coverage、fuzzing / mutation testing、署名付きマルチチャネル配布。
  この成熟度の競合は現状存在しない。
- **発見可能性がゼロ**: 紹介記事 0 本、デモなし、比較資料なし、
  awesome 系リスト未掲載、GitHub topics / description 未整備、
  README が英語のみ (日本の主要流入経路に乗らない)。

### 1.3 需要は実証済み — ただし誰も「ptuf」では検索しない

Zenn / Qiita / dev.to / 個人ブログには「Claude Code hooks で危険コマンドを
ブロックする」「rm -rf 事故と対策」系の記事が多数あり、いずれも
**自作の regex hook スクリプト**を提示している。つまり:

1. 課題意識を持つユーザは確実に存在する (記事が読まれ、bookmark されている)
2. ユーザの検索語は「ptuf」ではなく
   「Claude Code 危険コマンド ブロック」「Claude Code hooks ガードレール」
3. その検索結果に ptuf が一切出てこない

**核心課題は認知でも品質でもなく「検索導線上の不在」である。**

### 1.4 競合マップ

| アプローチ | 例 | 弱点 (= ptuf の訴求点) |
| --- | --- | --- |
| 自作 regex hook スクリプト | Zenn / Qiita 記事の bash + python 片 | bypass 耐性のテストがない (`rm -rf /` は止まるが `rm -rf "/"` や `$(echo rm) -rf /` は素通り)。ホストごとに書き直し。監査なし |
| 小規模 OSS hook 集 | agent-guardrails, OpSentry, claude-code_guard-rules | 単一ホスト前提が多い。ルールが regex 列挙でシェル構文を解釈しない。テスト・供給網保証が薄い |
| SaaS / API 判定 | Rulebricks 等 | ネットワーク依存・レイテンシ・機密コマンドの外部送信 |
| LLM に判定させる | permission prompt 任せ、LLM judge | 非決定的。プロンプトインジェクションで突破される |
| sandbox / コンテナ | Dev Container, sandbox-runtime | セットアップが重い。「壊せない環境」であって「壊す操作を検知して監査する」ものではない。併用は可能 (競合ではなく補完) |

ptuf の差別化は一行で言える:

> **自作 hook スクリプトの卒業先。シェル構文を解釈する決定的エンジン +
> bypass corpus / fuzzing で検証済みのルールを、6 エージェントに
> 1 コマンドで配る。**

## 2. ポジショニングとメッセージング

### 2.1 ポジショニング文

「コーディングエージェント用ガードレールの **standalone でテスト済みの
標準実装**。手書き hook の regex いたちごっこを終わらせる。」

### 2.2 メッセージの優先順位

訴求は「機能列挙」ではなく「読者がすでに持っている自作スクリプトとの差分」
で語る。刺さる順に:

1. **bypass 耐性が版管理されたテストで担保されている**
   (`tests/bypass/corpus.jsonl` + fuzzing + mutation testing)。
   自作 regex には絶対に真似できない点であり、最大の差別化。
2. **`ptuf init` 一発で 6 ホストに同じポリシー**
   (Claude Code / Codex / Copilot / Kiro / Cline / Cursor)。
   チームで複数エージェントが混在している現実に効く。
3. **fail-closed + self-protection** — エージェント自身が ptuf を
   無効化できない。hooks スクリプト自作勢が見落としがちな穴。
4. **JSONL 監査ログ** — 「何を止めたか」を後から説明できる。
   チーム / 企業導入の必須要件。

### 2.3 検索キーワード (コンテンツが取りに行く語)

- 日本語: `Claude Code 危険コマンド ブロック` / `Claude Code hooks
  ガードレール` / `rm -rf 事故 AI エージェント` / `Claude Code セキュリティ`
  / `Codex hooks` / `Cursor hooks 安全`
- 英語: `claude code hooks block dangerous commands` /
  `coding agent guardrails` / `pretooluse hook security`

## 3. フェーズ別実行計画

### Phase 0: 受け皿の整備 (即日〜1 週間) — 流入が来ても刺さる状態を作る

リポジトリ側 (このブランチで実装済みのもの):

- [x] README にバッジ・"Why ptuf?" 比較セクション・最新版インストール例
- [x] `README.ja.md` (日本語 README、日本の検索文脈に最適化)

**リポジトリ owner の手動アクション (API 不可のため要手作業)**:

- [ ] GitHub repo description を設定:
  `Deterministic guardrail for coding agents — blocks dangerous tool
  calls (rm -rf, curl|sh, credential leaks) via PreToolUse hooks.
  Claude Code / Codex / Copilot / Kiro / Cline / Cursor`
- [ ] GitHub topics を設定: `claude-code`, `codex`, `cursor`,
  `coding-agents`, `ai-agents`, `guardrails`, `security`, `hooks`,
  `pretooluse`, `rust`, `cli`
- [ ] Discussions を有効化 (質問の受け皿。issue より心理障壁が低い)
- [ ] Social preview 画像を設定 (OGP。X でリンクが流れたときの見え方が激変)
- [ ] asciinema か VHS (charmbracelet/vhs) で 20 秒デモ GIF を作り
  README 冒頭へ (`ptuf check --tool Bash 'rm -rf /'` → deny が映る絵)

### Phase 1: 日本での初期トラクション (1〜6 週間)

**主戦場は Zenn。** 記事は「ptuf 宣伝」ではなく「読者の課題解決」として書き、
解の一つとして ptuf に着地させる。各記事のアウトライン:

1. **「Claude Code の hooks 自作スクリプト、そのままで大丈夫?
   — bypass で検証してみた」**
   - 公開されている自作 hook 記事のパターンを 3〜4 個引用 (敬意を持って)
   - それぞれに対する素通り例を実演:
     クォート (`rm -rf "/"`)、変数展開、`bash -c`、パイプ経由、
     不可視文字インジェクション
   - 「regex 列挙では構造的に終わらない」→ シェル構文を解釈する
     決定的エンジン + 版管理された bypass corpus という設計の紹介
   - 末尾に `ptuf init claude-code` の 30 秒クイックスタート
   - これが最重要記事。検索語 1 群を全部取りに行く
2. **「AI エージェントの rm -rf 事故はなぜ繰り返すのか
   — 事例集と多層防御の設計」**
   - 公知の事故事例 (X / ブログ / HN で報告されたもの) を整理
   - CLAUDE.md (お願い) / permission (毎回ダイアログ) / sandbox (重い) /
     hook (決定的) の 4 層比較
   - hook 層の実装として ptuf。監査ログで「何が起きたか」を残す話まで
3. **「Claude Code・Codex・Copilot・Cursor、エージェントが増えるたびに
   hook を書き直していないか — 1 コマンドで 6 ホストに同じガードレール」**
   - マルチエージェント時代のポリシー管理問題
   - `ptuf init` の自動検出、`.ptuf.yaml` をリポジトリに commit して
     チーム全員に配る運用、plugin DSL での社内ルール追加

運用:

- 週 1 本ペース。各記事公開時に X へ投稿 (実演 GIF 添付)。
- X では記事告知以外に「今週 ptuf が止めたもの」系の小ネタ
  (audit ログから 1 事例) を週 1〜2 回。デモが命。
- Claude Code / AI コーディング系の勉強会・LT (オンライン含む) に
  記事 1 のショート版で登壇。5 分 LT 1 本は記事 1 本分以上の効果がある。
- 記事への反応 (コメント・引用) には全件返信。初期はこれが
  そのまま user interview になる。

### Phase 2: グローバル展開 (6〜12 週間、日本で反応を確認してから)

- 記事 1 を英訳して dev.to へ (`claude`, `ai`, `security` タグ)
- awesome 系リストへの掲載 PR:
  - `hesreallyhim/awesome-claude-code` (Tooling セクション)
  - awesome-claude / awesome-ai-agents / awesome-rust (cli カテゴリ) 等、
    PR 時点で active なものを選別
- Reddit: r/ClaudeAI, r/ChatGPTCoding に記事 1 英語版を
  「I tested popular DIY hook scripts against bypasses」の体で投稿
  (ツール宣伝体は弾かれる。検証レポート体で)
- **Show HN** は弾薬が揃ってから 1 回だけ:
  デモ GIF + 比較記事 + ある程度の stars (50+) が揃った時点。
  タイトル案: `Show HN: Ptuf – deterministic guardrails for coding
  agents (blocks rm -rf, curl|sh before they run)`
- Codex / Cursor / Cline の公式 Discord・フォーラムの hooks 関連
  スレッドで、質問への回答として登場する (宣伝でなく回答)

### Phase 3: チーム / 定着 (3 ヶ月目以降、Phase 1-2 の反応次第)

- 「チームで `.ptuf.yaml` を共有する」運用ガイド +
  CI での `ptuf check` 利用例 (GitHub Actions snippet)
- 企業ブログ / 商業メディア (Software Design 等) への寄稿打診
- roadmap の Gemini adapter 等は、実ユーザの要望が出た方を優先

## 4. やらないこと

- **広告・有料プロモーション** — この規模では ROI が出ない
- **マイナー配布チャネルの追加** (Nix, Scoop, …) — 要望が出てから。
  配布はすでに過剰供給で、ボトルネックは認知側
- **新機能開発の先行** — 3 ヶ月は「機能追加 < 発信」。
  roadmap 候補 (WASM runtime 等) は実ユーザの声が出るまで凍結が望ましい
- **star 乞い** — star はゴール (実利用) の遅行指標として扱う

## 5. 計測と判断基準

### 5.1 追跡する指標 (週次で記録)

| 指標 | 取得方法 |
| --- | --- |
| release asset downloads | GitHub Releases API (`download_count`) |
| Homebrew installs | `https://formulae.brew.sh/api/analytics` (tap は analytics 対象外のため参考値) |
| crates.io downloads | crates.io API |
| 外部 issue / Discussion / PR 数 | GitHub。**最重要のアウトカム指標** |
| 記事 PV / いいね | Zenn / dev.to ダッシュボード |
| GitHub traffic (views / clones / referrers) | Insights → Traffic (要 owner、14 日しか残らないので週次記録) |

### 5.2 マイルストーン

| 時点 | 期待ライン | 下回った場合 |
| --- | --- | --- |
| 30 日 | 記事 2 本公開、いずれかで 100+ いいね or はてブ。DL 週 +20 | 記事の切り口を変える (事故事例系は伸びやすい)。タイトル A/B |
| 60 日 | 外部からの issue / 質問が 1 件以上。DL 累計 200+ | 「外部の声ゼロ」なら導入摩擦を疑い、知人 3 人に導入してもらい録画観察 |
| 90 日 | 外部 issue/PR 3 件+、継続利用者の存在が会話で確認できる | 仮説転換: 個人開発者向けでなくチーム管理者向け (CI 統合 / ポリシー配布) に訴求軸を移す |

### 5.3 撤退・転換ではなく「軸替え」

需要 (自作 hook 記事群) は実在するため、3 ヶ月で結果が出なくても
撤退ではなくメッセージの軸替えで対応する。候補軸:
個人の事故防止 → チームのポリシー強制 → 監査・コンプライアンス。

## 6. 1 週間の標準ルーチン (author 向け)

- 月: 指標を 5.1 の表に従い記録 (15 分)
- 火〜木: 記事執筆 or 登壇準備 (合計 3〜4 時間)
- 金: 記事公開 + X 投稿 (公開は金曜午前〜昼が Zenn のゴールデン)
- 随時: 反応への返信、自作 hook 系の新着記事へのコメント
  (攻撃的にならず「この bypass は通ります、こういう対策があります」)
