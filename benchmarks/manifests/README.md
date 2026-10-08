# benchmark manifests（0034）

E2E benchmark の ground truth 正本（version 付き YAML）を置くディレクトリ。

- 1 ファイル = 1 `BenchmarkSuite`（`benchmark_model.load_manifest_file` が読む schema）。
- `benchmark_model.discover_benchmark_suites(<このディレクトリ>, registry_keys=...)` が
  `*.yaml`/`*.yml` を全て load し、`checks_covered_by_suites` が「vulnerable ground truth を
  持つ check（covered）」と「safe twin を持つ check」を導く。
- ある check の vulnerable/safe twin case をここに追加したら、`config/benchmark_gaps.yaml`
  からその check の gap を外す（外し忘れは registry 完全性テストが `redundant_gaps` で検出）。
- fixture 起動コードは manifest に埋めず、別の allowlist で管理する（設計 0034）。

`gate: gap` の case は covered に数えない。採点可能な twin が別 suite にある check は covered、
残る check は `config/benchmark_gaps.yaml` に明示し、未承認の未計測を
`uncovered`＝`INCOMPLETE` として検出する。明示 gap が残る registry は `PARTIAL` を維持する。

## 差別化 A/B（通常モード）

`differentiation_bypass.yaml` は既存の `payload_evolution` / `payload_mutation` を OFF
（`ScanEngineScanRunner(variant="conventional")`）と ON（`variant="vulix"`）にして、
同一条件の実スキャナを2回実行する。両経路で LLM・learning・adaptive は無効。
これは既存 bypass 波のアブレーションであり、外部 DAST 製品との比較や未実装 graph の効果を示さない。

```sh
WSCAN_E2E=1 python -m pytest -q -s tests/benchmarks/test_differentiation_e2e.py --basetemp=/tmp/differentiation-ab
```

各経路の `scorecard.json` / `scorecard.md` と、比較結果 `differentiation.json` /
`differentiation.md` が pytest の一時ディレクトリに保存される。source SHA、dirty 状態、manifest / registry
digest を記録する。両経路で実際に攻撃した vulnerable case の **FN→TP** だけが lift。
FN→FN は優位ゼロの実測であり、テスト成功は優位の実証を意味しない。safe twin は両経路で TN を要求する。

case に任意の `capability`（`transformation_graph` / `reward_search` / `state_graph` /
`dom_taint`）と `baseline_expected` を指定できる。省略時は capability なし、baseline の期待は
`expected` と同じ。`baseline_expected: safe` は OFF での「非検出期待」を表し、fixture の真の
脆弱性を安全へ変更しない。比較では期待外の OFF 結果を `baseline_mismatch` に記録する。

`differentiation_frontier.yaml` の SQLi 変換・結果件数の部分観測・認証状態付き BOLA・保存→閲覧の
chain は、脆弱 / 安全 twin を持つが対応 capability / 複数状態 / 多段 runner が未整備。
`gate: gap` を維持し、比較の `unmeasured` と capability 表の `null` に表示する。
保存型 chain は DOM taint の実装を試すケースではないため `dom_taint` と誤分類しない。
追加 capability は、それを実際に切り替える runner と採点可能な twin が揃ってから測定する。
