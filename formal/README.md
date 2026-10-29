# 形式モデル (TLA+ / Kani)

PBT (`proptest`) や fuzz は入力空間を **標本抽出** する。ここに置くモデルは、
有限に切った状態空間・入力空間を **網羅** して、設計書が約束する不変条件を
機械的に確かめる。どちらも `make check` には含めない (所要時間とツールの導入
コストのため)。nightly / 判定コアを変えた PR で手動実行する。

| 層 | ツール | 対象 | 実行 |
| --- | --- | --- | --- |
| 並行プロトコル / 判定の合成則 | TLA+ (TLC) | `formal/tla/*.tla` | `make tla` |
| Rust 実装そのもの | Kani (CBMC) | `src/**` の `#[cfg(kani)] mod verification` | `make kani` |

## TLA+ (`make tla`)

`scripts/formal-tla.sh` が TLC を回す。Java 11+ が必要で、`tla2tools.jar` は
版と SHA-256 を固定して `target/formal/` に 1 度だけ取得する
(`TLA_TOOLS_JAR` で既存の jar を指せる)。

- `formal/tla/<Spec>.cfg` — **成り立つべき** 構成。違反が出たら失敗。
- `formal/tla/violations/<Spec>[_x].cfg` — **違反が出るべき** 構成。修正前の
  バグや未決の設計課題を、反例が再現できる形で固定する。違反が出なくなったら
  (= コードかモデルが変わった) 失敗するので、設定を `formal/tla/` へ移す。

### `AuditLog.tla` — audit JSONL の並行追記

`JsonlSink::record` (flock + `O_APPEND` + `write_all`) と
`audit::read::open_snapshot` (shared lock で長さを取る) を、複数プロセス・
部分 write・**ロック保持中のプロセス死** (hook timeout の SIGKILL / ENOSPC) 付きで
モデル化する。

| 不変条件 | 意味 |
| --- | --- |
| `MutualExclusion` | 排他ロックを同時に持つ writer は 1 つ |
| `SnapshotEndsOnBoundary` | writer が死なない限り、snapshot は行境界で切れる |
| `AcknowledgedRecordsReadable` | `record` が `Ok` を返したレコードは必ず 1 行として読める |

**検出したバグ (修正済み)** — `violations/AuditLog_NoRepair.cfg`:

```
w1: lock → write "{w1 の前半" → 死亡 (改行なし、ロックは fd close で解放)
w2: lock → write "{w2 全体}\n" → Ok
file = "{w1 の前半{w2 全体}\n"   ← w2 の行は JSON として壊れ、reader は 1 行の invalid として捨てる
```

`Ok` を返した w2 のレコードが失われる。修正として writer はロック取得後に
末尾が `\n` でなければ `\n` を補ってから追記する
(`writer::terminate_torn_tail`、モデルでは `RepairTail = TRUE`)。
`AuditLog.cfg` は 3 writer でこの修正版を全探索する。

### `DecisionPipeline.tla` — 判定パイプラインの合成則

`Engine::decide` の rule ごとの `apply_rule_override` → `allowlist_hit_for` →
`demote_with_floor` → `aggregate` を、rule の属性 (`hardDeny` / `overridable`)・
rule の出力・`rules.<id>.enabled|decision`・allowlist・mode の **全組み合わせ**
(2 rule で 72 万状態) について評価し、`decision-model.md` /
`config-and-plugins.md` の約束を検査する。

| 不変条件 | 状態 |
| --- | --- |
| `HardDenyAlwaysBlocks` | 成立 |
| `DemotionOnlyLowersDeny` / `MonitorBlocksOnlyViaHardDeny` | 成立 |
| `AllowlistIdOnlyOnAllow` / `NoSpuriousEscalation` | 成立 |
| `StricterOverrideNeverWeakens` | 成立 (修正後) |
| `LockedRuleNotWeakenedByAllowlist` / `...ByMode` | **違反 (未決、下記)** |

**検出したバグ (修正済み)** — `violations/DecisionPipeline_NoFloor.cfg`:

```
mode = monitor, rule は ask を返す (overridable / 非 hardDeny)
rules.<id>.decision = deny   (より厳しくする override)
→ deny を monitor に降格して最終結果 Monitor (素通し)
override なしなら Ask だったので、厳しくした設定で結果が弱くなる
```

実機: `.ptuf.yaml` に `mode: monitor` と `rules: {core.git.reset-hard: {decision: deny}}`
を書くと `git reset --hard HEAD~1` が `ask` から `monitor` に変わっていた。
修正として、mode が降格した Deny は rule 自身の Ask を下回らない
(`filter::demote_with_floor`)。なお修正の初版は明示的な
`decision: monitor` (緩める override) まで Ask に戻してしまい、これも
`NoSpuriousEscalation` の反例としてモデルが検出した。

**未決の設計課題** — `overridable: false` の弱化:

`decision-model.md` は `overridable: false` を「下位 scope から decision を
変えられない / 無効化されない」と定めるが、次の 2 経路で結果が rule の出力を
下回る。

- `violations/DecisionPipeline_LockedByAllowlist.cfg`:
  `overridable: false` の rule (非 hardDeny) が `allowlists[]` で抑止される
  (`allowlist_hit_for` は `hard_deny` しか見ない)。
- `violations/DecisionPipeline_LockedByMode.cfg`:
  `overridable: false` の rule の Deny が `mode: monitor` で Monitor に降格される
  (`demote_for_mode` も `hard_deny` しか見ない)。

どちらも repo の `.ptuf.yaml` (信頼度が最も低い scope) から書ける。
`hardDeny` だけを最終防衛線とする現仕様なのか、`overridable: false` も
allowlist / monitor から守るべきなのかは仕様判断なので、コードは変えていない。

### `PackScopes.tla` — `packs.<prefix>.enabled` の scope 優先度

`config::merge` は pack key ごとに上位 scope の値で上書きし、
`is_pack_disabled` は rule id の **どれか 1 つの** prefix が `false` なら無効化する。

**未決の設計課題** — `violations/PackScopes.cfg`:

```
repo  (.ptuf.yaml)       packs: { core.network: { enabled: false } }
local (.ptuf.local.yaml) packs: { core:         { enabled: true  } }
→ core.network.* は無効のまま (より上位の local の enable が効かない)
```

同じ scope 内でも `core: false` + `core.network: true` は `core.network.*` を
無効にする。「上位 scope が勝つ」「より具体的な key が勝つ」のどちらにも
なっていないが、無効側に倒れるのは保守的でもあるため、コードは変えていない。

## Kani (`make kani`)

`cargo install --locked kani-verifier && cargo kani setup` で導入する
(`make kani` が `KANI_VERSION` を入れる)。harness は対象 module の末尾の
`#[cfg(kani)] mod verification` にあり、通常のビルド・テストには影響しない。

証明が実用時間で終わる harness だけを置く。`make kani` は nightly で 1–2 分程度。

| harness | 性質 |
| --- | --- |
| `audit::time::verification::civil_round_trip` | 4 桁年の全日付で `civil_from_days ∘ days_from_civil = id` |
| `audit::time::verification::days_round_trip` | 4 桁年の全日数で逆向きも恒等、出力日付も妥当 |
| `audit::time::verification::rfc3339_total_on_any_system_time` | 任意の `SystemTime` で overflow せず年は 1970..=9999 |

**検出したバグ (すべて修正済み)**

1. **`url.hostAny` の bypass**。IPv4 part の数値解釈を WHATWG の参照実装と
   比べる Kani harness は修正前のコードで即座に反例を出したが、修正後の
   **証明** は 30 分以内に終わらなかった。そのため同じ性質を有界網羅テスト
   `facts::url::tests::ipv4_number_matches_whatwg_exhaustively` (prefix 4 種 ×
   leading zero 0..=16 × 2 byte までの tail、約 4 万通り) として `make check`
   側に置いている。
   `parse_ipv4_number` が leading zero を含む生の桁数で 12 桁上限を判定していたため、
   `0x00000000000a9` (= 169) のような part を数値と認めず、host が正規化されなかった。
   WHATWG と curl はこれを `169.254.169.254` と解釈する。実機で
   `url.hostAny: ["169.254.169.254"]` の deny plugin を WebFetch
   `http://0x00000000000a9.0xfe.0xa9.0xfe/` / `http://00000000000000251.254.169.254/`
   がすり抜けた。あわせて `u64::from_str_radix` が受け付ける先頭 `+`
   (`1.2.3.+4` → `1.2.3.4`) も WHATWG に合わせて数値扱いしない。
2. **`rfc3339_utc` の overflow** (`rfc3339_total_on_any_system_time`)。
   `civil_from_days` の `era * 400` が i32 を超え、debug では panic、release では
   でたらめな年になっていた (時計が西暦約 21 億年を指す場合)。
   年 9999 の最終秒に clamp し、出力が常に `parse_rfc3339_to_secs` で読めるようにした。
3. **西暦 0 年 1–2 月の日付演算** (`civil_round_trip`)。
   `div_euclid` (床除算) に、C の切り捨て除算向けの `y - 399` 補正を重ねていたため、
   負の March-based year で era が 1 ずれていた。現状の呼び出し経路では
   到達しない (負の Unix 時刻は弾かれる) が、補正を外して全域で逆関数にした。
