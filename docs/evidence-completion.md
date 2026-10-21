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

The initial instrumented contract covers page-level CORS captured wildcard/credentials
analysis and the active Origin reflection comparison, plus CORS finding reverification.
Both page decisions are required. A zero-Finding successful CORS comparison can be
complete; a zero-Finding timeout remains partial. Selecting other scanners, field-level
no-op calls, API template paths or unknown auxiliary paths conservatively keeps their
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
