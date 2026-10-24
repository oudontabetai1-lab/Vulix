# Evidence completion in normal scans

Normal scan reports now show **Evidence completion** separately from check selection,
Finding counts, verification state and the lifecycle status `done` or `aborted`.
The dashboard shows the same completion state when a scan finishes and after reconnect.
Existing findings and detection decisions are preserved.

- `COMPLETE`: every required decision for every planned unit was persisted, execution
  finished successfully, and the recorder reports no evidence gaps or write failures.
- `PARTIAL`: decisions were recorded, but execution did not finish successfully, or an
  outcome was timeout, blocked, skipped, unexecutable, or an error. These outcomes
  provide evidence of an attempt; they do not establish successful negative coverage.
- `EVIDENCE_INCOMPLETE`: a required decision is missing, planning is empty or unknown,
  a path has no instrumented detector contract, or evidence logging failed.

Expectations are saved to `probe_attempts_manifest.json` before the attack queue runs.
They use hashes of the existing checkpoint unit identity (URL, field, form/location and
check), so another field's evidence cannot satisfy the unit. Task-local attribution is
stored as `completion_unit` on `probe_attempts.jsonl` records. Completion is computed
from these persisted detector decisions, not from HTTP counts or checkpoint done bits.
The manifest and `evidence.json` coverage include per-check and per-unit states.

The instrumented contract covers page-level CORS captured wildcard/credentials
analysis and the active Origin reflection comparison, plus CORS finding reverification.
Both page decisions are required. A zero-Finding successful CORS comparison can be
complete; a zero-Finding timeout remains partial. Selecting uninstrumented scanners, field-level
no-op calls, unknown API template paths or auxiliary paths conservatively keeps their
evidence incomplete. This change does not claim all-transport or per-payload completeness.
Chain, adaptive, multi-parameter, DOM, OOB and other detector paths still need their own
definitive outcome contracts. Check selection `COMPLETE` continues to mean selection
coverage only.

Configured exclusions keep their existing execution behavior; known excluded URLs and
field names retain an explicit `excluded_by_configuration` reason in the plan. A selected check with no
applicable discovered work has an empty plan and is explicitly incomplete, rather than
being declared tested through an empty-set success. Excluded or unreachable discovered
units are not inferred to have succeeded. Planning cannot enumerate undiscovered inputs.

Resume reuses the original output directory to restore planned identities and decisions
from the manifest/JSONL. It preserves attempt IDs, parent IDs and unfinished execution.
A completed checkpoint without corresponding evidence cannot satisfy this gate. If a
resume writes to a different output directory, historical evidence is unavailable there
and skipped historical units remain incomplete. Missing or corrupt persisted plan/evidence
state fails closed. The gate does not manufacture observations or resend completed work.

Run the opt-in Chromium acceptance with:

```sh
WSCAN_E2E=1 python -m pytest -q tests/test_evidence_completion_e2e.py
```

It runs vulnerable/safe CORS twins, a real timeout, an actual filesystem logger failure,
separate-process checkpoint resume, and an old checkpoint with missing evidence through
the production engine. It also checks the dashboard after reconnect. Normal test
collection does not launch these scans.

## Common browser and HTTPX requests

Common query/form submissions through Playwright and canonical JSON submissions through
HTTPX now carry explicit scanner, injection-point identity, execution wave and role.
Browser context is bound on the worker's capture at navigation/submission, and the outgoing
request retains it for late response callbacks. Setup navigation, assets and iframe loads
do not inherit an attack role. HTTPX stores context on each actual request, including
distinct redirect requests. Ambiguous or unbound traffic cannot complete a detector unit.

`probe_attempts.jsonl` remains append-only: each row has its own immutable `attempt_id`.
For newly scoped requests, `record_kind=request` identifies one outgoing request;
`observation` rows refer to it with `request_attempt_id`, and `decision` rows refer to
both the outgoing request and the exact observation via `parent_id`. Header and body
observations can therefore share a request without creating additional probe attempts.
`record_kind=payload` records preparation, which does not prove a request was sent.
Legacy rows (including rows without `record_kind`) retain their existing semantics and IDs.
Manifest `total` and `by_role` retain event accounting, including failed writes;
`logical_requests` counts only newly scoped outgoing request attempts. Delivery is
established separately by correlated observations. This counter is not an estimate of
all traffic from uninstrumented transports. Existing HTTP/payload logs remain available.
The request/response bodies use hashes and lengths; captured headers and URLs use the
existing central redaction policy. Captured bodies are not copied into ledger excerpts.

Definitive decisions are persisted at the existing SQLi error, boolean, timing and
authentication-bypass branches, and at XSS dialog/reflection decisions. SQLi requires
both measured baselines; its boolean comparison references the exact partner control.
XSS HTML-attribute/JavaScript-string equivalence probes also record their own baseline,
attack and broken-quote control group. A comparison whose baseline marker was not
observable is skipped, rather than counted as a successful negative. Canonical JSON XSS
records HTML reflection decisions, which do not establish browser execution or confirmation.
Finding confirmation and reverification policy are unchanged.

A common detector unit can be complete only when every scoped request has durable
delivery/body evidence and every attack has a definitive decision referencing the exact
unit, field/location, baselines and required controls. Missing, foreign, wrong-unit or
undecided late attempts fail closed. Timeouts, transport/oracle errors, policy skips,
dispatcher blocks and unexecutable carriers remain visible and cannot become safe negatives.
Write failures retain the existing quarantine/incomplete behavior. Resume rebuilds these
relationships from the same JSONL source, including mixed legacy/current logs.

Whole-check completion remains conservative: unknown auxiliary, adaptive, multi-parameter,
DOM/flow, custom protocol and verification paths still have incomplete plans. A complete
common field unit does not claim that all paths of that scanner, or the whole scan, are
complete. Finding/Hypothesis artifact grounding and LLM evidence summaries remain outside
this contract. There are no new configuration switches or changes to probe order/count.

Real loopback HTTPX acceptance and opt-in Chromium query/form twins can be run with:

```sh
python -m pytest -q tests/test_shared_probe_evidence.py
WSCAN_E2E=1 python -m pytest -q tests/test_shared_probe_evidence_e2e.py
```

These exercise the production callers with vulnerable/safe twins, explicit comparison
controls, failures, duplicate hooks, concurrent equal names, missing/wrong/late evidence,
and separate-process restart/resume. Candidate and confirmed counts are recorded separately;
only complete common units qualify as successful safe-negative evidence.

### Browser page and flow operations

The ordinary page scheduler now persists a bounded browser chain for `dom_xss`
query/form attacks and `js_static` snapshot analysis. Typed `browser` rows share
`probe_attempts.jsonl`, its append-only IDs, manifest and quarantine behavior.
They contain hashed input manifests and explicit page, operation, snapshot and
parent identities. They do not create HTTP requests or increase `logical_requests`.
Actual prerequisite-flow and restore navigations retain separate concrete request
rows with `discover` and `cleanup` roles.

Browser completeness uses its own persisted predicate. Static analysis requires
its HTML snapshot and every referenced external script body: no referenced scripts
is a known empty input set, whereas a missing body is incomplete. Existing network
fallbacks still serve detection, but cannot establish snapshot completeness.
Duplicate analysis and skipped flow actions likewise cannot establish a negative.
DOM decisions require a captured operation, a complete parent snapshot, a concrete
request/response, the installed sink hook, and the scanner's existing marker oracle.
Verification additionally refers to the matched attack decision. `None`, exceptions,
missing bodies/parents, scope refusal and recorder errors cannot become complete
negative decisions. Candidate and confirmed Finding policy is unchanged.

Dialog callbacks capture their originating page and operation before awaiting;
replayed callback objects do not add another dialog event. Recovery records link
the triggering dialog, page replacement and actual restore navigation. A replacement
page cannot borrow an old page's snapshot to complete verification. Completed
checkpoint markers alone remain insufficient evidence, and missing historical proof
does not trigger a replay of an otherwise fully checkpointed state-changing flow.

This covers the first ordinary page/flow slice. API-template and TLS-seed calls,
other page scanners, auxiliary/adaptive/context probes, protocol internals and
artifact/LLM grounding retain explicit incomplete contracts. It does not establish
whole-check, whole-browser or all-transport completion.

Run the focused persisted-causality tests and opt-in production Chromium acceptance:

```sh
python -m pytest -q tests/test_browser_operation_evidence.py
WSCAN_E2E=1 WSCAN_BROWSER_ACCEPTANCE_DIR=/path/to/new-empty-directory \
  python -m pytest -q tests/test_browser_operation_evidence_e2e.py
```

The Chromium fixture exercises vulnerable/safe query and form twins, successful and
intermediate-failure prerequisites, actual dialog-flood recovery, and separate-process
checkpoint resume with and without retained evidence. Every rerun needs a fresh
acceptance directory; previous failed artifacts remain separate.


### Passive HTTP header decisions

通常スキャンの `clickjacking` と `security_headers` は、既存の共有 API GET の実リクエストと
応答を参照する `passive_decision` 行を記録します。ブラウザの非 HTTP snapshot 行へ置き換えず、
ページ監査の共有取得回数も増やしません。redirect 後は実際の最終 hop の応答を参照します。
応答ヘッダの全入力は hash と長さ、中央の伏字処理と上限を適用した excerpt で保持します。
空のヘッダ辞書も有効な入力ですが、応答なし・非対象 content-type・非 2xx・取得失敗は
安全という判定になりません。

ページ単位の完了には、clickjacking の framing 判定、または security_headers のヘッダ欠落
6 条件と CSP/HSTS 値の 2 条件がすべて保存され、対応する実入力との相関が必要です。
`security_headers` の既存の再検証も元の一致判定と新しい取得応答を参照します。既存の
検出条件・再検証の戻り値・Finding の確証ポリシーは保持されます。clickjacking に専用の
再検証は追加しません。

native network capture への fallback は引き続き検出に使いますが、この契約では元の永続 HTTP
identity を証明できないため証跡は不完全のままです。未知の補助経路などの plan も残るため、
このページ単位の完了は check 全体や全 transport の完了を意味しません。古い行や checkpoint
だけで不足した判定を補うことはできず、logger failure は不完全として表示します。

```sh
python -m pytest -q tests/test_passive_page_evidence.py
WSCAN_E2E=1 WSCAN_PASSIVE_ACCEPTANCE_DIR=/path/to/new-empty-directory \
  python -m pytest -q tests/test_passive_page_evidence_e2e.py
```

実 Chromium fixture は本番 ScanEngine の脆弱・安全ツイン、非空の HTTP 500 応答、logger failure、
別プロセス resume と証跡欠落を検証します。candidate と confirmed を分けて数え、server の実測
受信数と共有 GET の台帳件数を照合します。resume の既存 crawl GET と、完了済みの監査 GET の
再送抑制は別に確認します。再実行では新しい空の artifact directory を使ってください。
