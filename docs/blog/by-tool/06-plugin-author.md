# 社内固有ルールを YAML プラグインに切り出した話 (`ptuf plugin test` でレッド→グリーン)

## 経緯

うちの repo には「`curl` を直接叩かないで、社内の fetch ヘルパを使う」という運用ルールがあります。built-in pack には流石にそんな専用ルールは無いので、`ptuf` の YAML プラグインで自前のルールを書いてみました。

`ptuf` のプラグインは Rust や WASM ではなく **YAML だけ** で書けて、`tests:` セクションをそのまま `ptuf plugin test` で実行できる、というのが気に入りました。

## ルールの本体

`acme-security.yaml` を `~/.config/ptuf/plugins/` あたりに置きます。

```yaml
apiVersion: ptuf.dev/v1
kind: Plugin

metadata:
  name: acme.security
  version: 0.1.0
  description: Acme team-specific rules

capabilities:
  events: [PreToolUse]
  tools: [Bash]
  requires: [tool, event, shell.argv]

rules:
  - id: acme.security.no-curl
    title: Block raw curl
    severity: high
    defaultDecision: deny
    when:
      all:
        - event: PreToolUse
        - tool: Bash
        - shell.argv:
            headAny: [curl]
    reason: Avoid raw curl in this repository.
    remediation:
      - Use the project fetch helper instead.
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "curl https://example.com"
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
```

ポイントは:

- `defaultDecision: deny` で「既定は止める」
- `when:` の `shell.argv.headAny: [curl]` で「コマンド先頭が `curl`」を捕捉
- `tests.deny` / `tests.allow` で **そのルール単体** の動きを CI で守る

## テスト実行

```bash
ptuf plugin test ~/.config/ptuf/plugins/acme-security.yaml
```

deny ケースが `Deny` を返し、allow ケースが `Allow` を返したら通ります。注意点として、`ptuf plugin test` は **そのプラグイン rule だけ** を評価する単体テストです。built-in pack や aggregate まで通したい場合は `ptuf eval` の方を使います。

## config から読み込ませる

書いただけでは効かないので `~/.config/ptuf/config.yaml` で参照します。

```yaml
version: 1
plugins:
  - path: ~/.config/ptuf/plugins/acme-security.yaml
    enabled: true
```

`enabled: false` にすると参照を残したまま読み込みだけ止められるので、トラブル時の切り戻しが楽でした。

## `when:` DSL でできることの範囲

`docs/design/config-and-plugins.md` の DSL 表が一次情報です。今回使ったのは `shell.argv.headAny` ですが、他にも:

- `shell.pipeline` で `curl ... | bash` のようなパイプ流れを捕捉
- `path.filePathPrefixAny` で特定ディレクトリへの書き込みを制限
- `url.hostAny` で特定ホスト宛の WebFetch を制限
- `sensitive.pathKindAny` で機密分類 (`aws`, `ssh` 等) を引っ掛ける
- `all` / `any` / `not` で論理結合

があります。ルールが LLM 判定ではなく **正規化された fact** に対するマッチで書けるので、テストの再現性がかなり高いのが嬉しいです。

## つまずいたところ

- `capabilities.requires` に `shell.argv` を入れ忘れて load エラーになりました。実装は `requires` を明示的に検証します
- `tests.allow` を空のままにしたら「いつ deny されないか」を後から思い出せなくて辛かったので、最低 1 件は書いた方が良いです

## 関連

- [`docs/design/config-and-plugins.md`](../../design/config-and-plugins.md) — Plugin schema と `when:` DSL
- [`docs/design/policy-packs.md`](../../design/policy-packs.md) — built-in との重複を避ける参考
