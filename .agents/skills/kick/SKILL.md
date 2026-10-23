---
name: kick
description: >
  指定した issue を修正し、実機で確かめ、$wrapup を通してから issue を閉じる PR を
  出し、merge まで CI を緑に保つ。user が「$kick #123 #456」のように issue 番号を
  渡したときに発動する。
argument-hint: "<issue番号> [<issue番号>...]"
---

# kick

指定された issue をすべて片付ける。PR は 1 本。issue は作らない。

不明点があれば作業を止めて user に質問する。推奨する回答を添える。コードを
読めば分かることは質問しない。

## 手順

1. **読む**: issue と関係する `docs/design/` の節・`docs/adr/` を読み、受け入れ
   条件を issue ごとにまとめる
2. **直す**: issue ごとに失敗するテストを書いてから修正し、1 コミットにする。
   仕様が変わるなら `docs/design/` も更新する。認識する形を足すときは、認識できない
   入力がどうなるかも決める（黙って Allow しない。`docs/design/decision-model.md`
   の「fail-closed の境界」）。bypass を塞いだら `tests/bypass/corpus.jsonl` に
   追記する。`make check` を通す
3. **実機で確かめる**: release ビルド（`make build`）の `ptuf` に再現ケースを
   流す（`ptuf check --tool <name> <command>` や hook payload を stdin に渡す
   `ptuf hook <agent>`）。判定ロジック（`src/rules/**` / `src/engine/**` /
   `src/facts/**` / `src/plugin/**`）を変えたら `make pbt-quick` と `make e2e` を
   走らせ、差分を 1 件ずつ仕分ける。隣の不具合や読めない形が見えたら、軽いものは
   その場で直し（別コミット）、3 をやり直す
4. **$wrapup** を実行する。修正を取り込んだら 3 をやり直す
5. **PR を出す**: 本文は英語。対象の issue を閉じる。中心は issue から読み取れない
   判断・意図・捨てた案。実機の結果も載せる。diff を見れば分かることは書かない。
   最後に「Found, not fixed」の節を置き、途中で見つけたことを 1 件 1 行で書く
6. **起票しない**: 重いものは 5 の節に書いて終わり。user が必要なものだけ issue に
   する。例外は、再現手順のある bypass（危険な操作が Allow される）・誤 Deny・
   クラッシュで、open issue・`docs/design/roadmap.md` のどれにも入らないもの。
   PR 1 本につき 1 件まで。本文に bypass（危険な形の見逃し）か false positive
   （安全な形を止める）かを書く
7. **追い続ける**: 15 分ごとに PR を確認し CI を緑に保つ。レビューに追従する。
   merge / close されたらやめる

## 軽い・重い

軽い: 触っている module の中で直せて、`docs/design/` の仕様を変えず、テスト込みで
数十行。見つけた順に直し、やり直しは合計 3 周まで。重い: それ以外、または 3 周を
超えて残ったもの。
