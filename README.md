# ColdLedger Pharmaceutical Cold-Chain Operations Lab

Dependency-free Python reference implementation for temperature-sensitive pharmaceutical distribution. It models inventory expiry, chain-of-custody, telemetry correction, packaging qualification, dry-ice depletion, freezer allocation, customs holds, serialization, recalls, release decisions, vehicle compartment compatibility, returns, SLA calendars and cross-dock state.

Runtime third-party dependencies: none.

## Controlled-substance handoff flow (`coldledger.controlled`)

`HandoffFlow` strings handoff, offline credentials, the inventory ledger and the
audit trail into a single replayable, tamper-evident event-sourced flow:

- **Idempotent commands** — every command carries a client idempotency key.
  Replays return the *same* recorded receipt (`duplicate=True`, identical
  event/manifest digests); a key reused for a different command is rejected.
- **Hash-chained event log** — each event stores the SHA-256 digest of the
  previous event on its stream over canonical JSON, so any retroactive edit
  breaks verification.
- **Replay** — inventory postings, the global audit trail and sealed manifests
  are pure projections of the event log; `HandoffFlow.replay(store)` rebuilds
  byte-identical state, and dedup keys are reconstructed from the log.
- **Sealed evidence** — sealing requires dual sign-off (creator + witness),
  attested offline credentials for both parties and available stock; it books
  the custody transfer and seals a `Manifest` over balances, the audit head and
  the event chain.
- **Corrections are append-only** — a later correction posts a compensating
  ledger entry (never an update or delete) and seals a *new* manifest chained to
  the previous one; the initial sealed evidence remains unchanged.
- **Verification** — `verify_all()` folds the stored log into fresh projections
  and compares balances, audit digests and manifest chains.

See `tests/test_controlled_handoff.py` for the full walkthrough.
