# npm 配布設計 (npm-distribution)

本書は ptuf を npm registry 経由で配布するための設計である。一次情報は
`src/` 配下の実装と `.github/workflows/release.yml` / `dist-workspace.toml`
であり、本書はその上に載せる配布層の契約と意図を整理する。

ステータス: **実装中 (v0.5.0 npm publish 準備)**。`npm/` テンプレート、
shim、stamp/smoke scripts、CI smoke、release publish job は実装済み。
残りは npm 側の package/org 予約、初回 bootstrap publish、Trusted
Publishing 設定、実 release/PR 上の cargo-dist plan 検証である。

## 目的

- Node.js エコシステムのユーザが `npm install -g ptuf` / `npx ptuf` で
  導入できるようにする
- 既存配布チャネル (shell/powershell installer, Homebrew, crates.io,
  cargo-binstall, mise/aqua) と同水準の検証可能性
  (checksum + attestation + provenance) を保つ
- hook ホットパスのレイテンシ特性を劣化させない

## Non-goals

- cargo-dist の npm インストーラー (install 時 fetch 型) の採用
- Node.js API としてのライブラリ公開 (`require('ptuf')`)。配布するのは
  CLI バイナリのみ
- `aarch64-pc-windows-msvc` (Windows ARM) の初期サポート

## 方式決定: platform-package 方式 (esbuild / Biome 型)

npm での Rust CLI 配布には大別して 2 方式ある。

| 観点 | fetch 型 (cargo-dist npm installer) | platform-package 型 (本設計) |
| --- | --- | --- |
| install 時ネットワーク | GitHub Releases への fetch が必須 | npm registry のみ (通常の依存解決) |
| オフライン / プロキシ / GitHub 遮断 CI | 失敗する | 動作する |
| `--ignore-scripts` 環境 | postinstall 依存のため動作しない | install スクリプト不使用のため動作する |
| lockfile integrity による改竄検証 | fetch した内容は対象外 | バイナリ含め全て対象 |
| 生成コスト | `dist generate` 再実行 (手パッチ再適用が必要) | `release.yml` へのジョブ追記のみ |
| 実装コスト | 小 | 中 (テンプレート + shim + publish ジョブ自作) |

**platform-package 型を採用する。** 決定理由:

1. install スクリプトを一切持たないパッケージはサプライチェーン監査上の
   攻撃面が小さく、`--ignore-scripts` を強制する組織でも動作する。
   ptuf 自体がガードレールツールであり、配布物が「postinstall で外部から
   実行ファイルを取得する」形はプロダクトの思想と矛盾する。
2. バイナリが npm registry に載るため、lockfile の integrity hash と
   `npm publish --provenance` による検証チェーンが npm 標準機構で完結する。
3. fetch 型は `dist generate` の再実行を要求する。`release.yml` は
   zizmor 対応の手パッチ済み (`dist-workspace.toml` の
   `allow-dirty = ["ci"]` 参照) であり、再生成はパッチ全再適用の
   リスクを伴う。platform-package 型は `publish-crates-io` と同型の
   ジョブ追記で済み、既存生成部分に触れない。

## パッケージ構成

```
ptuf (メインパッケージ)
├── bin/ptuf.js                        # 依存ゼロの JS ランチャー
└── optionalDependencies (全て同一バージョンに厳密 pin):
    ├── @ptuf/cli-darwin-arm64         # aarch64-apple-darwin
    ├── @ptuf/cli-darwin-x64           # x86_64-apple-darwin
    ├── @ptuf/cli-linux-x64-gnu        # x86_64-unknown-linux-gnu
    ├── @ptuf/cli-linux-x64-musl       # x86_64-unknown-linux-musl
    ├── @ptuf/cli-linux-arm64-gnu      # aarch64-unknown-linux-gnu
    ├── @ptuf/cli-linux-arm64-musl    # aarch64-unknown-linux-musl
    └── @ptuf/cli-win32-x64            # x86_64-pc-windows-msvc
```

- 各プラットフォームパッケージは実バイナリ 1 個 (`bin/ptuf` または
  `bin/ptuf.exe`) を同梱し、`package.json` の `os` / `cpu` / `libc`
  フィールドで npm が適合する 1 個だけを選択インストールする。
  プラットフォームパッケージ自身は `bin` エントリを持たない
  (`node_modules/.bin` を汚さない。esbuild と同じ)。
- メインパッケージだけが `bin: { "ptuf": "bin/ptuf.js" }` を公開する。
- optionalDependencies のバージョンはメインと**完全一致で pin** する
  (`"0.6.0"` 形式、range 禁止)。バージョン skew による
  shim ↔ バイナリの不整合を構造的に排除する。
- `engines: { "node": ">=18" }`。shim は `node:` プレフィックスの
  標準モジュールのみ使用する。

プラットフォームパッケージの `package.json` 例:

```json
{
  "name": "@ptuf/cli-linux-x64-musl",
  "version": "0.0.0-dev",
  "description": "ptuf binary for x86_64-unknown-linux-musl",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "https://github.com/watany-dev/ptuf" },
  "os": ["linux"],
  "cpu": ["x64"],
  "libc": ["musl"],
  "files": ["bin/ptuf"]
}
```

`version` はリポジトリ内テンプレートでは `0.0.0-dev` の placeholder とし、
publish ジョブが tag から stamp する (後述の三重整合検証)。

### 命名とスコープ

- メインパッケージ名 `ptuf` は 2026-07-07 時点で npm registry 上に
  未公開 (`npm view ptuf name version --json` が E404)。v0.5.0 の
  npm 実装前に予約 publish する。取得不能になった場合は全体を
  `@watany/ptuf` + `@watany/ptuf-cli-*` に切替える。
- プラットフォームパッケージ用に npm org `ptuf` (スコープ `@ptuf`) を
  取得する。代表パッケージ `@ptuf/cli-linux-x64-musl` も 2026-07-07
  時点で未公開 (`npm view @ptuf/cli-linux-x64-musl name version --json`
  が E404)。org には 2FA を必須設定する。

## JS ランチャー (shim) の契約

shim は hook プロトコルの**忠実なプロキシ**でなければならない。契約:

1. **stdout / stderr / stdin を素通しする** (`stdio: 'inherit'`)。
   shim 自身は正常経路で stdout に 1 byte も書かない
   (decision JSON は host が stdout を parse する契約。
   `docs/design/cli-and-hooks.md` 参照)。8 MiB stdin 境界
   (`tests/e2e_heavy.rs` の boundary axis) も無加工で通す。
2. **exit code を正確に転送する**。バイナリが signal で死んだ場合は
   同一 signal を自分に再送出して終了する
   (`process.kill(process.pid, signal)`)。
3. **依存ゼロ**。`node:child_process` / `node:path` のみ。
   libc 判定も `detect-libc` を入れず
   `process.report.getReport().header.glibcVersionRuntime` の有無で
   自前判定する (Minimal Dependencies 原則)。
4. **バイナリ解決順序**: ① 環境変数 `PTUF_BINARY_PATH` (テスト・退避用の
   明示 override) → ② `require.resolve('@ptuf/cli-<platform>/bin/ptuf')`
   → ③ 解決失敗時は stderr にサポート対象プラットフォーム一覧と
   代替インストール手段 (`docs/install.md`) を出して非 0 で終了する。
   hook 経路でこの失敗が起きても host 側は fail-closed 契約
   (`docs/design/decision-model.md`) に従い deny 側へ倒れる。

## ホットパス設計: Node を hook 経路に入れない

ptuf は tool call ごとに spawn される。`tests/e2e_heavy.rs` の
latency_budget axis は per-call 2 秒 (warm) を張っており、Node 起動の
数十 ms は予算内ではあるが、ネイティブ配布との恒常的な品質差になるため
ホットパスから排除する。

既存実装がそのまま解になる: `ptuf init` は
`std::env::current_exe()` で hook コマンドのパスを解決する
(`src/init/mod.rs`、各 adapter の `src/init/*.rs`)。shim 経由で
`ptuf init` を実行しても、**init を実際に実行するのはネイティブバイナリ**
なので、hook 設定に書き込まれるのはプラットフォームパッケージ内の
バイナリ絶対パス (`.../node_modules/@ptuf/cli-<platform>/bin/ptuf`)
であり、以降の hook 呼び出しは Node を経由しない。

この性質は暗黙の副産物ではなく**契約**に昇格させる:

- contract test を追加する — npm レイアウトを模した配置から
  `init --dry-run --json` を実行し、レンダリングされる hook command が
  JS shim を指さないこと (パスが `.js` でなくバイナリ実体であること) を
  固定する。
- `docs/install.md` の npm セクションに「hook はネイティブパスを直接叩く。
  `npm update` 後もパスは安定する (パッケージディレクトリは
  バージョン非依存)」を明記する。

注意点: プロジェクトローカル install (`npm i -D ptuf`) では hook パスが
リポジトリ内 `node_modules` を指す。`node_modules` 削除で hook が壊れるが
fail-closed で deny に倒れるため安全側。この挙動も install.md に明記する。

## `ptuf update` の npm ガード

現状の `select_strategy` (`src/update/mod.rs`) は
`CargoInstall | PrebuiltInstaller` の 2 戦略で、cargo bin 配下でなければ
無条件に prebuilt installer へフォールバックする。npm 管理の実行ファイルで
`ptuf update` を実行すると、prebuilt installer が `$CARGO_HOME/bin` に
別コピーを置き、npm 管理側は古いまま残る (README 記載の Homebrew の
既知問題と同型)。npm では最初からガードする:

- `Strategy` に外部管理検知を追加する
  (`ExternallyManaged { manager: PackageManager }` 相当。
  variant 追加に伴う match 網羅は既存の `FakeExeLocator` seam で
  テスト駆動する)。
- 判定: `current_exe()` の (canonicalize 後の) パス成分に
  `node_modules` を含む場合は npm 管理と判定し、update を実行せず
  `npm update -g ptuf` (ローカル install なら `npm update ptuf`) を
  案内するメッセージを出して終了する。exit code は既存の
  「update 不能・案内あり」経路に合わせる。
- Homebrew (`Cellar` / `linuxbrew` パス成分) の同型ガードは本設計の
  スコープ外だが、enum 設計は追加できる形にしておく (`PackageManager`
  を non-exhaustive にはしない。追加時に match を明示的に増やす)。

## ビルドターゲット追加: `aarch64-unknown-linux-musl`

npm ユーザは Alpine コンテナ (Apple Silicon 上の Docker、Graviton) での
利用が多く、linux-arm64-musl の欠落は npm 経路では実質的な障害になる。

- `dist-workspace.toml` の `targets` に `aarch64-unknown-linux-musl` を
  追加済み。ビルドマトリクスは `dist plan` が実行時に算出するため
  `release.yml` の再生成は**不要**。
- リスク: ARM musl のクロスツールチェーン。`[dist.dependencies.apt]` に
  必要パッケージ (`musl-tools` 相当の aarch64 版、または
  cargo-dist が ARM runner を割り当てる場合はネイティブ musl-tools) を
  追加する。**実装前に PR 上で `pr_run_mode` 相当のビルド確認を行う**
  (release.yml は `pull_request` トリガで `dist plan` を回すので、
  ターゲット追加の妥当性は plan 出力で先に検証できる)。
- 追加ターゲットのアーカイブは他ターゲットと同じ命名規約
  (`ptuf-<target>.tar.gz`、`Cargo.toml` の binstall pkg-url と整合) に乗る。

## リリースパイプライン: `publish-npm` ジョブ

`release.yml` 末尾に `publish-crates-io` と同型の手書きジョブとして追記
する。cargo-dist 生成部分には触れない。

```
publish-npm:
  needs: [plan, host]
  if: host 成功 && publishing == 'true'
  permissions:
    contents: read
    id-token: write        # npm provenance / OIDC 用
```

ステップ設計:

1. **checkout** — `npm/` テンプレートと stamp スクリプトを取得
   (`persist-credentials: false`、action は SHA pin。既存ジョブの
   ハードニング基準に合わせる)。
2. **Release アセット取得** — `gh release download "$TAG"` で
   全ターゲットのアーカイブと `SHA256SUMS` を取得する。
3. **検証** — repack する前に必ず検証する (無検証の repack は
   attestation チェーンを切断する):
   - `sha256sum -c SHA256SUMS` (全対象アーカイブ)
   - `gh attestation verify <archive> --repo watany-dev/ptuf` を
     アーカイブごとに実行
4. **stamp + 展開** — `npm/scripts/stamp.mjs` (単一スクリプト、
   smoke テストと共用) が: tag からバージョンを取り、
   `Cargo.toml` バージョンとの一致を検証し (crates.io ジョブと同じ
   三重整合を npm にも適用: tag ↔ Cargo.toml ↔ package.json)、
   各テンプレートの `0.0.0-dev` を置換し、アーカイブから抽出した
   バイナリを `npm/platform/<pkg>/bin/` に配置する。
5. **publish (順序固定)** — **プラットフォームパッケージ 7 個 →
   メインパッケージの順**。逆順だと optionalDependencies が一瞬
   解決不能になる。各 publish 前に `npm view <pkg>@<version>` で
   published 済みを検知して skip し、部分失敗後の workflow re-run を
   冪等にする (release workflow は `cancel-in-progress: false` で
   直列化済み)。
6. **provenance** — `npm publish --provenance --access public`。
   認証は npm の **Trusted Publishing (OIDC)** を採用し、長寿命
   `NPM_TOKEN` を GitHub Secrets に置かない。ただし Trusted Publisher の
   紐付けはパッケージ登録後にしか設定できないため、**初回 publish のみ**
   短命の granular token で手動 bootstrap し、直後に token を revoke して
   OIDC 設定に切替える (運用手順として `docs/RELEASING.md` のリリース
   ランブックに記載する)。

### SHA256SUMS の対象拡張 (前提変更)

現状 `release.yml` の `Generate SHA256SUMS` は verified-install 用の
3 アーカイブ + installer 2 種 + SBOM のみを対象にしており、attestation
(`actions/attest` の `subject-checksums`) もこのリストに閉じている。
npm は**全 7 ターゲット**のバイナリを repack するため、ステップ 3 の
検証が成立するように `SHA256SUMS` と attestation の対象を全ターゲット
アーカイブへ拡張する。これは npm と無関係にも検証カバレッジの改善であり、
独立の先行変更として切り出せる。

## リポジトリ内レイアウト

```
npm/
├── ptuf/                          # メインパッケージ テンプレート
│   ├── package.json
│   ├── bin/ptuf.js                # shim (版管理・レビュー対象)
│   └── README.md                  # npm ページ用の最小 README
├── platform/
│   ├── cli-darwin-arm64/package.json
│   ├── ...                        # 7 テンプレート (bin/ は publish 時に注入)
│   └── cli-win32-x64/package.json
└── scripts/
    ├── stamp.mjs                  # version stamp + バイナリ配置 (publish / smoke 共用)
    └── smoke.mjs                  # pack → 一時 dir へ install → 動作検証
```

テンプレートと shim は版管理してレビュー可能に保つ。publish 時に生成される
のは version 文字列とバイナリ配置のみで、生成物の差分が最小になる。

## テスト戦略

このリポジトリの品質ゲート構成 (`docs/design/testing.md`) に合わせ、
npm 層も「契約を版管理されたテストで固定する」:

| 層 | 内容 | 実行タイミング |
| --- | --- | --- |
| contract test | `init` が npm レイアウト配置でネイティブパスを書くこと | `make check` (`tests/contracts.rs` 拡張) |
| unit test | `select_strategy` の `node_modules` 検知分岐 | `make check` (`src/update/mod.rs` 既存 seam) |
| npm smoke | pack → install → 動作検証 (下記) | PR CI 新ジョブ + release 前 |
| publish dry-run | stamp.mjs の三重整合検証 + `npm pack` 成功 | PR CI |

npm smoke (`npm/scripts/smoke.mjs`) の検証項目:

1. `ptuf --version` が tag バージョンを返す — 実装済み
2. hook decision 往復 — deny 入力で exit code / stdout JSON が
   ネイティブ直叩きと**バイト一致**する (shim の透過性)
   — 実装済み
3. 8 MiB stdin 境界の通過 — 未実装 (smoke 拡張候補)
4. signal 転送 (SIGTERM でバイナリが死んだとき shim が同 signal 終了)
   — 未実装 (smoke 拡張候補)
5. `init --dry-run --json` の hook command がバイナリ実体を指す
   — smoke と `tests/contracts.rs` で実装済み

CI は初期実装として `ubuntu-24.04` (glibc) で host 向けバイナリを
release ビルドし、publish と同じ `stamp.mjs` でパッケージを組み立てて
検証する。`alpine` コンテナ (musl 判定) / `macos-latest` /
`windows-latest` は smoke 安定後に追加する。

`make e2e` への npm axis 追加は初期スコープ外とし、smoke の安定稼働後に
検討する (roadmap 候補)。

## ドキュメント更新

- `README.md` / `README.ja.md` — Install に npm 経路を追加済み
  (`npm install -g ptuf`)。`ptuf update` が npm 管理を扱わないことを
  Homebrew と同じ粒度で注記済み。
- `docs/install.md` — npm セクション追加済み: provenance 検証手順
  (`npm audit signatures`)、ローカル install 時の hook パスの寿命、
  オフライン環境での利点。
- `docs/RELEASING.md` — release runbook に npm publish の部分失敗
  リカバリ手順 (re-run 冪等性、published 済み skip の挙動) と
  初回 bootstrap 手順を追記済み。

## 実装マイルストーン

| # | 内容 | 状態 | 依存 |
| --- | --- | --- | --- |
| M-NPM1 | `SHA256SUMS` / attestation の全ターゲット拡張 | 実装済み | なし (独立先行) |
| M-NPM2 | `aarch64-unknown-linux-musl` ターゲット追加 + PR plan 検証 | 実装済み、PR/CI plan 検証待ち | なし |
| M-NPM3 | `npm/` テンプレート + shim + `stamp.mjs` + smoke CI ジョブ | 初期実装済み | M-NPM2 |
| M-NPM4 | `ptuf update` の npm ガード + contract test | 実装済み | なし |
| M-NPM5 | `publish-npm` ジョブ + 初回 bootstrap + OIDC 切替 + docs | workflow/docs 実装済み、npm 側 bootstrap/OIDC 設定待ち | M-NPM1〜4 |

## 未決事項

- npm 上の `ptuf` パッケージ名と代表 platform package は未公開確認済み。
  残りは npm アカウントで `ptuf` package と `@ptuf` org を実際に予約し、
  Trusted Publishing を設定できる状態にすること。取得不能時は
  `@watany` スコープへの切替で本設計はそのまま成立する。
- aarch64-musl のクロスビルドが現行 runner 構成で通るか (M-NPM2 の
  PR 検証で確定させる)
- npm smoke を `make check` 対象に含めるか (Node 依存が増えるため、
  初期は CI 専用ジョブとし `make check` には含めない方針)
