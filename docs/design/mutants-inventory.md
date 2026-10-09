# Mutation testing 棚卸し

`make mutants` (`cargo-mutants`) の結果を記録し、生き残った (`MISSED`)
ミュータントを分類して、テストの追加 / バグ修正の issue と対応付ける。
運用手順は `docs/design/testing.md` の "Mutation testing" を参照。
T (テスト不足) の消化状況は #264 で追跡する。

## 運用

| 層 | コマンド | タイミング | ブロッキング |
|---|---|---|---|
| diff | `make mutants-diff` (`BASE=origin/main`) | PR CI (`ci.yml` の `mutants-diff` job) | しない (`continue-on-error`、結果は step summary と artifact) |
| full | `make mutants` | nightly (`nightly.yml` の `mutants` job) | しない (report を artifact に出力) |
| 範囲指定 | `make mutants ARGS="--no-config -f src/self_paths.rs"` | 手動 | - |

- `CARGO_PROFILE_DEV_DEBUG=0` で debuginfo を落とし、mutant ごとのビルドを軽くする
  (`Makefile` の `MUTANTS_ENV`)。
- `.cargo/mutants.toml` に `examine_globs` があると `-f` が効かず、常にフルスコープ
  (1139 件) になる。1 ファイルだけを回すときは `--no-config` を併用する
  (この場合 `exclude_re` も外れる)。
- root で実行すると `run_audit_unreadable_file_is_io_error` がベースラインで失敗する (#257)。
  root のコンテナでは `-- -- --skip run_audit_unreadable_file_is_io_error` を付けて回避する。
- ループ index の `+=` → `-=` / `*=` は無限ループになってタイムアウトするだけでカバレッジの
  穴を示さないため、`exclude_re` で除外する。ただし `xargs_command_start` は MISSED を
  隠さないよう、あえて除外していない。

### MISSED の分類

| 記号 | 意味 | 対応 |
|---|---|---|
| **B** | ミュータントの周辺で実バイパス / 誤検知を確認した | bug issue を起票し、修正 PR で回帰テストと corpus を追加する |
| **T** | 振る舞いは正しいが、テストがそれを固定していない | example-based テストを追加して潰す |
| **E** | 等価またはほぼ等価 (性能のための fast path など) | `exclude_re` に入れるか、ここに理由を残す |

優先度: **P1** = hardDeny / deny 判定に直結する、**P2** = ask 判定 / 補助ロジック。

## 2026-10 フル実行 (main `5a3d91a`)

スコープ: `decision.rs` / `rules/**` / `engine/**` / `plugin/dsl.rs` /
`facts/shell.rs` / `config/merge.rs`。

| 総数 | caught | missed | unviable | timeout | 所要時間 (`-j 2`) |
|---|---|---|---|---|---|
| 1128 | 912 | 89 | 92 | 35 | 約 55 分 |

timeout 35 件はすべて `src/facts/shell.rs` のループ index (`read_word` 19、
`read_heredoc_body` 9、`absorb_parens` 2 など)。これらの `+=` 系は `exclude_re` に追加した。

### MISSED の内訳

| 場所 | ミュータント (抜粋) | 分類 | 優先度 | 関連 issue |
|---|---|---|---|---|
| `facts/shell.rs` `tokenize` 519-522 | heredoc `<<-` / タグ前の空白スキップの境界 | B | P1 | #249, #250 |
| `facts/shell.rs` `tokenize` 608 / 624 | fd 付き redirect (`2>` / `n<`) の index 演算 | T | P2 | #258 |
| `facts/shell.rs` `read_heredoc_body` 669-707 | 本文の開始位置・タブ除去・終端判定 | B | P1 | #249, #250 |
| `facts/shell.rs` `read_word` 775-797 | バッククォート / ダブルクォート内のエスケープ処理 | B | P1 | #251, #254 |
| `facts/shell.rs` `read_word` 824 | 閉じクォートの境界 | T | P2 | - |
| `facts/shell.rs` `plain_run_len` 844-852, `is_plain_word_byte` 877 | 性能のための fast path (遅い経路と結果が同じ) | E | - | - |
| `facts/shell.rs` `absorb_parens` 908-928 | `$(...)` の入れ子の深さ / 本文の切り出し | T | P1 | #250 |
| `facts/shell.rs` `take_redirect_target` 1010 / 1016 | redirect target に含まれる `$(...)` の折り込み | T | P1 | #258 |
| `facts/shell.rs` `xargs_command_start` 1186-1195, `xargs_flag_takes_value` 1204 | オプションの値の読み飛ばし | B | P1 | #255 |
| `facts/shell.rs` `short_flag_cluster_contains` 1268 | `-` 単独 / `--` の除外 | T | P2 | - |
| `facts/shell.rs` `is_env_assignment` 1285 | `=x` / 不正なキーの扱い | T | P2 | - |
| `plugin/dsl.rs` `subst_tree_has_from` 239 | `-> true` | T | P2 | - |
| `rules/destructive_rm.rs` `normalize_rm_target` 151 | 末尾 `/` の除去条件 `>` → `<` | E (ほぼ等価) | - | - |
| `rules/injection_content.rs` `scan_bytes` 218 | 行番号の `+=` → `*=` (finding の行番号が未検証) | T | P2 | - |
| `rules/sensitive_bash_read.rs` 99 | `has_reader && has_sensitive` → `\|\|` | T | P1 | - |
| `rules/sensitive_net.rs` 72 / 91 / 101 / 104 / 108 | `/dev/tcp` redirect の判定 (true / false 両方が生存) | B | P1 | #262 |
| `rules/sensitive_read.rs` 54 | MCP tool かつ paths が空の場合 | T | P2 | - |
| `rules/git/argv.rs` `is_git` 17 / `is_truthy` 102 | `-> true` | T | P1 | #259 |
| `rules/git/argv.rs` `git_subcommand` 38-47 | グローバルオプションの読み飛ばしガード | B | P1 | #263 |
| `rules/git/bypass.rs` `matches_no_verify` 90 | `-n` クラスタ判定 | B | P1 | #260, #261 |
| `rules/git/clean.rs` 35-38 | `-f` / `-d` / `-x` のフラグ集約 | T | P2 | - |
| `rules/git/push.rs` 23-26 / 56-57 | force / delete の判定 | B | P1 | #261 |

## 2026-10 拡張スコープ実行 (main `5a3d91a`)

`--no-config -f src/self_paths.rs -f src/facts/path.rs -f src/facts/sensitive.rs -f src/facts/url.rs`
(`self_paths.rs` は今回 `examine_globs` に追加。`facts/path.rs` / `sensitive.rs` / `url.rs` は
試験的に実行しただけで、まだスコープには入れていない)。

| 総数 | caught | missed | unviable | timeout | 所要時間 (`-j 3`) |
|---|---|---|---|---|---|
| 227 | 190 | 22 | 15 | 0 | 約 13 分 |

`facts/path.rs` は MISSED 0 件。

| 場所 | ミュータント (抜粋) | 分類 | 優先度 | 備考 |
|---|---|---|---|---|
| `self_paths.rs` `collect_with_env` 183 / 211 / 241 (9 件) | `err.kind() == NotFound` のガード | E | - | `NotFound` の arm と `Err(_)` の arm がどちらも `continue` なので、ガードは冗長。Tidy First で arm を 1 つにまとめれば消える |
| `self_paths.rs` `ProtectedKinds::push_unique` 74 | `<` → `<=` | T | P2 | 容量 (`CAPACITY`) の上限に達したケースのテストがない |
| `facts/sensitive.rs` `fold_char` 245-252 | Cyrillic / Greek の `к о τ υ х` の arm 削除 | T | P2 | homoglyph の正規化で、一部の文字にしかテストがない |
| `facts/sensitive.rs` `matches` 271 / `classify_into_filtered` 316 | `mask & bit` → `mask \| bit` | E | - | 事前フィルタの mask を無効にしても、最終判定は regex が行う (性能上の差だけ) |
| `facts/sensitive.rs` `is_mask_trigger` 338 / `needle_mask` 349-372 | fast path / 早期 return | E | - | 同上 |
| `facts/url.rs` `is_valid_scheme` 61 | `\|\|` → `&&` | T | P2 | `git+ssh` / `svn+ssh` など `+ - .` を含む scheme のテストがない |

### ミュータントを起点に見つかった不具合

mutation の MISSED 周辺を手で検証して見つかった不具合は、すべて issue に登録した。

| issue | 概要 | 重大度 |
|---|---|---|
| #247 | 改行がコマンドの区切りとして扱われない | Critical |
| #248 | 単独の `&` がコマンドの区切りとして扱われない | Critical |
| #249 | heredoc 開始行の残りが本文に吸収される | Critical |
| #250 | stdin 経由のシェル実行 (`bash <<EOF` / `<<<` / `echo \| bash`) と heredoc 内の `$()` | High |
| #251 | ダブルクォート内のバッククォート | High |
| #252 | `timeout` / `nohup` などの wrapper が剥がされない | High |
| #253 | 複合コマンド (`( )` / `{ }` / `if` / `for` / `while` / `!` / `time` / `exec` / `builtin`) | High |
| #254 | ANSI-C クォート `$'…'` | Medium |
| #255 | xargs / `env -S` / `find -ok` の command start の誤認 | High |
| #256 | self-protection: `..` を含むパスで未作成の保護対象ファイルを作成できる | High |
| #257 | root 環境でテストが失敗する | Low |
| #258 | self-protection: `>\|` / `&>>` / `<>` と install / dd / truncate / rsync など | High |
| #259 | git の `--config-env` と `GIT_CONFIG_COUNT` / `KEY` / `VALUE` | High |
| #260 | 誤検知: `git commit -m<msg>` で msg に `n` が含まれると no-verify になる | Medium |
| #261 | git の長オプションの一意 prefix 省略 (`--no-veri` / `--delet` / `--har`) | High |
| #262 | `/dev/tcp` への送信が `>\|` / `<>` / `exec N<>` で deny から ask に格下げされる | High |
| #263 | `git --attr-source X` / `--config-env X` でサブコマンドを誤認する | High |

検証の結果、対象外と判断したもの:

- `rm -rf /.` 系 — GNU rm は `.` / `..` を末尾に持つ引数を拒否する
- `X=/; rm -rf $X` — 変数展開は既知の制約 (ADR の範囲内)
- `git -ccore.hooksPath=…` — git は `-c` の値の連結形を受け付けない
- `cat .env > /dev//tcp/…` — bash は `/dev/tcp` を文字列の完全一致で扱うため送信は成立しない
