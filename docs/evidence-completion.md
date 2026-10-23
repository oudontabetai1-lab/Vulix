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
