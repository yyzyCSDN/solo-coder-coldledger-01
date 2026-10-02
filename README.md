# ColdLedger Pharmaceutical Cold-Chain Operations Lab

Dependency-free Python reference implementation for temperature-sensitive pharmaceutical distribution. It models inventory expiry, chain-of-custody, telemetry correction, packaging qualification, dry-ice depletion, freezer allocation, customs holds, serialization, recalls, release decisions, vehicle compartment compatibility, returns, SLA calendars and cross-dock state.

Runtime third-party dependencies: none.

## Controlled handoff workflow

`coldledger.custody.ControlledHandoffWorkflow` joins controlled-drug handover, offline credentials, inventory and audit into one append-only, replayable event log.

- Clients submit a client-generated `command_id`; replaying the exact same command returns the stored event and receipt.
- Both parties independently sign a canonical terms digest with HMAC-backed offline credentials before a handoff can be sealed.
- Sealing performs the inventory transfer, binds the result into the sealed event digest, and appends an audit record under the workflow lock.
- Pending handoffs can be cancelled. Sealed handoffs can only be reversed or receive append-only addenda; both operations are dual-signed and link back to the original sealed digest.
- `events()` produces a hash-chained global log. `replay(...)` verifies each digest, rebuilds state and commands, reuses or re-posts inventory entries, and rebuilds the audit trail.
