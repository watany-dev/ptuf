# zghalint v0.0.1-rc.1 ドッグフード — ptuf CI 評価

`watany-dev/zghalint` の最初の公開プレリリース (`v0.0.1-rc.1`,
commit `7600004`) を、このリポジトリの GitHub Actions に対して走らせた記録。
目的は ptuf のワークフロー品質を測ることと、RC を実リポジトリで消費したときの
検出精度・欠け・配布経路を測ること。

実行日: 2026-09-09。バイナリはタグをソースから `zig build -Doptimize=ReleaseFast`
して得た (`zghalint v0.0.1-rc.1`)。GitHub Release の asset は空で、README が案内する
`zghalint-linux-x86_64.tar.gz` は 404 だった。Release ワークフロー
(`watany-dev/zghalint` run `34303774946`) は `gh release create` が
「同じタグのリリースが既にある」で落ちており、Action 経由の消費はまだできない。

## 1. 検出範囲

引数なし実行は次を自動発見した (6 ファイル)。欠落はなし。

| パス | 診断 |
| --- | --- |
| `.github/workflows/ci.yml` | あり |
| `.github/workflows/nightly.yml` | あり |
| `.github/workflows/release.yml` | あり (大半) |
| `.github/workflows/audit.yml` | なし |
| `.github/workflows/publish-crates.yml` | なし |
| `.github/dependabot.yml` | あり |

`--quick` とネットワーク有りは同一の 28 件。SC003–SC008 は毎回
`github api unreachable` でスキップされた。同じ環境で `curl` / `gh api` は
`api.github.com` に届く。`SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` を
渡しても変わらず、ネットワーク依存ルールはこのランでは評価不能。

終了コード 1 (error が 1 件)。初回サマリ: error 1 / warning 18 / info 9。
§4 の 2 件を入れたあと: error 1 / warning 17 / info 7 (25 件)。消えたのは
`ci.yml` BP001 と Dependabot DEP001 × 2。

## 2. 判定

凡例: **TP** = ルール通りで実害または直すべき、**受容** = ルール通りだが意図的、
**FP** = ルールの適用を誤っている、**FN** = あるべき指摘が無い。

### 2.1 error

| ルール | 箇所 | 判定 | 理由 |
| --- | --- | --- | --- |
| SEC021 | `release.yml` `publish-npm` checkout `ref: inputs.tag` | 受容 | `workflow_dispatch` の回復経路。dispatch できる主体は既に write を持ち、続く `gh release download` は同名リリースが無いと落ちる。checkout をタグに合わせるのは npm 梱包スクリプトをそのリリースの tree から読むため。allowlist 検証を足しても SEC021 は黙らない |

### 2.2 warning — 直した / 直さない

| ルール | 件数 | 判定 | メモ |
| --- | --- | --- | --- |
| BP001 missing timeout | 8 | TP 1 + 受容 7 | `ci.yml` の `zizmor` だけ手書きジョブで漏れ。残り 7 は cargo-dist 生成の `release.yml` (再生成で消える) |
| PERF003 fail-fast: false | 3 | 受容 | `ci.yml` / `nightly.yml` はクロス OS・fuzz 行列を最後まで走らせるため明示。`release.yml` は dist の成果物行列 |
| BP007 obfuscation | 2 | 受容 (過検知気味) | `curl … \| sh` の cargo-dist installer と rustup。ピン済み URL。同じ系統の `bash <(curl …)` (actionlint インストール) は **未検出** → FN |
| EXPR007 unsound-condition | 2 | **FP** | `env.PRERELEASE_FLAG: ${{ cond && '--prerelease' \|\| '' }}` は値を作る ternary。`if:` ではない。autofix は条件比較に書き換えようとして意味を壊す |
| SC001 unpinned image | 1 | 受容 | `container: ${{ matrix.container && matrix.container.image \|\| null }}`。digest は dist plan の実行時値 |
| SEC018 persist-credentials | 1 | 受容 | `publish-homebrew-formula` が tap へ `git push` する。ファイル内コメントで意図を明記済み |
| PERF001 setup-node cache | 1 | 受容 | `publish-npm` は `package-manager-cache: false` を明示。成果物検証が主で lockfile install ではない |

### 2.3 info

| ルール | 件数 | 判定 | メモ |
| --- | --- | --- | --- |
| DEP001 dependabot cooldown | 2 | TP | 両 ecosystem に `cooldown.default-days: 7` を足した |
| BP002 unnamed run step | 5 | 受容 | 全部 `release.yml` の dist 生成ステップ (`id: plan` など) |
| PERM001 contents: write | 1 | 受容 | `host` の `gh release create`。コメント済み。zizmor の excessive-permissions と同じ信号 |
| SEC019 secret in `with:` | 1 | 受容 | `token: ${{ secrets.HOMEBREW_TAP_TOKEN }}` は checkout の入力。env 経由にすると action が読めない |

### 2.4 出なかったもの (良い沈黙 / 欠け)

良い沈黙:

- SEC001 (unpinned action) — SHA ピンが徹底されている
- SEC002 / SEC005 / SEC007 / SEC015 — 危険トリガや persist+artifact の組み合わせが無い
- `audit.yml` / `publish-crates.yml` は診断ゼロ

欠け (zghalint 側、ptuf の zizmor 設定と突き合わせ):

- **SEC023 は `cargo publish` + `CARGO_REGISTRY_TOKEN` を見ない**。zizmor
  `use-trusted-publishing` は `publish-crates.yml` を指摘対象にしており、
  `.github/zizmor.yml` で意図的に suppress している。crates.io Trusted Publishing
  への未移行は既知で、zghalint はこのギャップを再発見しない
- **BP007 は `bash <(curl …)` を見逃す**。`ci.yml` の actionlint インストールが該当。
  `curl \| sh` は取る
- ネットワークルール (SC003–SC008, SC002 の一部) はこの環境では評価不能

## 3. actionlint / zizmor との役割分担

ptuf は既に `actionlint` と `zizmor` (persona auditor) を PR ゲートに載せている。
今回 zghalint が足した価値:

- Dependabot cooldown (zizmor は見ない)
- `timeout-minutes` 漏れ (actionlint も必須にはしない)
- `workflow_dispatch` checkout ref (zizmor の untrusted-checkout 系より
  dispatch 入力まで含む)
- 式の ternary を条件と誤認する EXPR007 — 今はノイズ

zizmor が抑えて zghalint が再指摘しなかったもの (良い): SHA ピン、
`persist-credentials: false` の既定、template injection を env 経由にした
`github.ref_name`。`release.yml` の cargo-dist パターンは zizmor.yml で
ファイル単位 suppress しており、zghalint は同じファイルをルール単位で
騒ぐ。ゲート化するなら `.zghalint.yml` で `release.yml` を ignore するか、
BP001/BP002/PERF003/SC001 を落とす必要がある。

## 4. ptuf 側で入れた修正

RC の指摘のうち、手書きワークフローで安くて正しいものだけ直した。

1. `zizmor` ジョブに `timeout-minutes: 10` (BP001)
2. Dependabot 両更新に `cooldown.default-days: 7` (DEP001)

`release.yml` は触っていない。再生成で消える変更を増やすより、
CONTRIBUTING.md の手パッチ一覧へ timeout を足すのは cargo-dist 更新のときにやる。

## 5. CI への zghalint 組み込み

今回は入れない。

- RC にダウンロード可能なバイナリが無い。`uses: watany-dev/zghalint@v0.0.1-rc.1`
  は Action が release archive を取りに行って 404 になる
- ソースから Zig 0.15.2 で毎 PR ビルドするのはゲートとして重い
- error の SEC021 は受容なので、ゲート化には ignore 設定が先

バイナリ付きの tag が出たら、`actionlint` / `zizmor` の隣に SHA ピンで足すのが
次のドッグフード。そのとき `.zghalint.yml` で `release.yml` を dist 生成物として
ignore し、手書き workflow だけを fail 対象にする。

## 6. zghalint RC へのフィードバック (消費側から)

1. **Release asset が無い** — タグは付いているが archive が上がっていない。
   ドッグフードの第一関門で詰まる
2. **EXPR007 は `env:` の ternary を `if:` 扱いする** — cargo-dist が常用する
   `cond && 'flag' \|\| ''` が全部ヒットする。値文脈では黙るべき
3. **BP007 は `curl \| sh` だけ見て process substitution を見ない**
4. **SEC023 に crates.io / `cargo publish` が無い** — Rust リポジトリでは
   zizmor より弱い
5. **GitHub API クライアントがこの環境で常に unreachable** — システム CA でも
   `gh` でも通るホストで SC003–SC008 が死ぬ。`--quick` と差が無い

1 が直るまで ptuf CI には載せられない。2–4 はゲート化した瞬間にノイズか見逃しになる。
