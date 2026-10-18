# SentinelLoop: Phased Build Plan

Definition of done: a judge loads an incident, inspects evidence, sees a real Jev decision, approves a safe simulated response, and verifies the outcome, all in one UI.

Dev A = backend (Phases 1-4). Dev B = frontend + demo (Phases 0, 5-6). Frozen contract after Phase 0.

## Phase 0: Contract and skeleton (hour 0-2, both devs)
- Repo layout: `backend/` (FastAPI, Pydantic, stdlib `sqlite3`), `frontend/` (Vite, React, TS, Tailwind), `data/scenarios/`.
- Write the Pydantic models once: `Event`, `Asset`, `Incident`, `Decision`, `PolicyResult`, `VerificationResult`. Export OpenAPI; Dev B mocks against it.
- API contract:
  - `POST /incidents/load?scenario=ransomware` returns Incident
  - `GET /incidents/{id}` returns timeline, assets, evidence
  - `POST /incidents/{id}/decide` returns Decision (Jev)
  - `POST /incidents/{id}/actions` returns PolicyResult (allowed / needs_approval / blocked)
  - `POST /incidents/{id}/actions/{aid}/approve|reject`
  - `POST /incidents/{id}/verify` returns VerificationResult
  - `PATCH /incidents/{id}/assets/{host}` for the criticality what-if
- Get the Jev API key; test the 3-question payload in the Jev playground and save the real request/response as a fixture.
- Exit: both sides run, a stub endpoint returns fixture JSON to the UI.

## Phase 1: Logs and detection (hour 2-6, Dev A)
- Hand-write `ransomware.json` (3 servers: server-a, server-b, payments), plus a benign-noise scenario.
- Normalize timestamps and host IDs.
- 4-5 plain-function rules: mass file rename/encryption, shell spawn from office app, SMB auth burst, new outbound beacon, backup deletion. Each rule emits an alert with event refs.
- Exit: unit test, scenario in, expected alerts out.

## Phase 2: Incident context (hour 6-9, Dev A)
- Group alerts by host and time window into a timeline, attach criticality and an explicit `uncertainties` list, store in SQLite.
- Exit: `GET /incidents/{id}` returns a complete Incident that matches the contract.

## Phase 3: Jev decision service (hour 9-13, Dev A)
- Build the one request with `Choice`, `Score`, `Noul`, using the playground-validated question definitions.
- Server-side key from env. Timeout and retry once. Validate the response shape. Normalize to `Decision`.
- On any failure return `Decision(status="unavailable")`, never a made-up result.
- Test with the saved fixture and a mocked failure.
- Exit: a real Jev call works end to end and the fixture tests pass.

## Phase 4: Policy, approval, simulation, verification (hour 13-18, Dev A)
- Policy (deterministic): allowlist `{isolate_host, collect_evidence, escalate}`. `isolate_host` on a critical asset requires approval; anything off-list is blocked. Jev unavailable falls back to `escalate`. Write every decision to an audit table.
- Simulator: a mock `isolate_host` marks the host isolated and replays the post-action events from the scenario file.
- Verifier: compare the post-action events to the scenario's `expected_outcome`. Include a scenario where it fails.
- Exit: the blocked, approved, verified-pass and verified-fail paths all work through the API.

## Phase 5: Dashboard (hour 5-20, Dev B, parallel on mocks, then switch to the real API)
- Panels: timeline, assets and evidence, decision card (choice + alternatives, urgency, Noul probability labelled "uncertain signal"), policy and approval controls, verification result.
- Criticality what-if toggle that re-runs decide and shows the changed result and approval requirement.
- Exit: the full flow works in the UI against the real backend.

## Phase 6: Evaluation, polish, rehearsal (hour 20-24, both)
- 5-6 labelled scenarios: true ransomware, false positive, ambiguous, critical asset, missing logs, Jev down.
- Script prints latency, agreement with the expected choice, evidence correctness, false escalations and unsafe actions blocked. Report only the numbers we actually measure.
- Rehearse the 5-minute demo (load, context, decide, blocked action, approve, verify pass, verify fail, what-if). Cache a fallback recording in case the network or Jev fails live.

## Cut order if time runs short
1. CSV ingestion (JSON only)
2. Extra scenarios (keep 3)
3. Latency charts (keep a plain number)

Never cut: the real Jev call, the policy gate, the verification step.

## Risks
- Jev response shape differs from the docs: Phase 0 fixture catches this early.
- Live network at the demo: have the fallback recording.
- Scope creep: the "not building" list in `context.txt` is binding.
