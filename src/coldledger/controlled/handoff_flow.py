"""Controlled-substance handoff orchestration.

Handoffs, offline credentials, the inventory ledger and the audit trail are one
event-sourced flow:

* Commands are deduplicated by an idempotency key; replays of a duplicate
  command return the *same* recorded result instead of being applied twice.
* Every event extends a per-stream SHA-256 hash chain (``previous`` digest),
  so the recorded history is tamper-evident and fold order is deterministic.
* Inventory postings, audit records and sealed manifests are pure
  projections of the event log: :meth:`HandoffFlow.replay` rebuilds identical
  state from the :class:`~coldledger.storage.event_store.EventStore`.
* Sealing captures an evidence :class:`Manifest` over balances, the audit head
  and the event chain. Once sealed, earlier events/manifests are immutable; a
  correction posts a compensating ledger entry (never an update/delete) and
  seals a new manifest chained to the previous one.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from threading import RLock
from typing import Iterable

from ..audit.trail import AuditTrail
from ..inventory.ledger import InventoryLedger
from ..storage.event_store import EventStore
from .evidence import Manifest, canonical, fingerprint

GENESIS = "GENESIS"
CREATOR = "creator"
WITNESS = "witness"
ROLES = frozenset({CREATOR, WITNESS})

KINDS = (
    "created", "credential_attested", "signed",
    "stock_received", "sealed", "corrected",
)

# stock_received is booked on an account stream, everything else on a handoff stream
HANDOFF_STREAM = "handoff:"
ACCOUNT_STREAM = "account:"


@dataclass(frozen=True)
class Credential:
    holder: str
    credential_id: str
    issued_at: datetime
    asserted_at: datetime
    digest: str


@dataclass(frozen=True)
class FlowEvent:
    stream: str
    sequence: int
    kind: str
    at: datetime
    actor: str
    payload: dict
    previous: str
    digest: str

    @staticmethod
    def digest(stream, sequence, kind, at, actor, payload, previous) -> str:
        # Projection fields (leading underscore, e.g. the sealed manifest
        # digest) are excluded so the event hash does not depend on derived
        # evidence: the fold recomputes the manifest and cross-checks it.
        logical = {k: v for k, v in payload.items() if not k.startswith("_")}
        raw = canonical([
            stream, sequence, kind,
            at.astimezone(timezone.utc).isoformat(), actor, logical, previous,
        ])
        return hashlib_sha256(raw)

    @classmethod
    def decode(cls, stored) -> "FlowEvent":
        # Strip only the transport envelope fields; projection fields such as
        # idempotency_key / _manifest_digest stay inside the logical payload.
        reserved = {"_at", "_actor", "_previous", "_digest"}
        p = {k: v for k, v in stored.payload.items() if k not in reserved}
        return cls(
            stored.stream, stored.sequence, stored.kind,
            datetime.fromisoformat(stored.payload["_at"]),
            stored.payload["_actor"], p,
            stored.payload["_previous"], stored.payload["_digest"],
        )

    def encode_payload(self) -> dict:
        p = dict(self.payload)
        p.update({
            "_at": self.at.astimezone(timezone.utc).isoformat(),
            "_actor": self.actor,
            "_previous": self.previous,
            "_digest": self.digest,
        })
        return p


def hashlib_sha256(raw: str) -> str:
    import hashlib
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HandoffState:
    handoff_id: str
    revision: int = 0
    status: str = "open"  # 'open' | 'sealed'
    created_event: int | None = None
    creator: str | None = None
    witness: str | None = None
    drug_code: str | None = None
    quantity: Decimal | None = None
    from_location: str | None = None
    to_location: str | None = None
    signatures: tuple[tuple[str, str, str, datetime], ...] = ()  # role, actor, ref, at
    credentials: tuple[Credential, ...] = ()
    manifests: tuple[Manifest, ...] = ()

    def role_signed(self, role: str) -> bool:
        return any(s[0] == role for s in self.signatures)

    def dual_signed(self) -> bool:
        return self.role_signed(CREATOR) and self.role_signed(WITNESS)

    def credentials_complete(self) -> bool:
        holders = {c.holder for c in self.credentials}
        return self.creator in holders and self.witness in holders

    def ready_to_seal(self) -> bool:
        return self.status == "open" and self.dual_signed() and self.credentials_complete()


@dataclass(frozen=True)
class Receipt:
    stream: str
    revision: int
    kind: str
    at: datetime
    idempotency_key: str
    duplicate: bool
    event_digest: str
    command_fingerprint: str = ""
    sealed_manifest: str | None = None


def command_fingerprint(stream: str, kind: str, at: datetime, actor: str,
                        payload: dict) -> str:
    """Stable hash of the command itself, independent of stream position.

    Underscore projection fields (the fingerprint itself, the sealed manifest
    digest) are excluded so the hash is not self-referential.
    """
    logical = {k: v for k, v in payload.items() if not k.startswith("_")}
    return fingerprint([stream, kind, at.astimezone(timezone.utc), actor, logical])


@dataclass
class _StreamView:
    revision: int = 0
    head: str = GENESIS
    state: HandoffState | None = None
    audits: AuditTrail = field(default_factory=AuditTrail)


class HandoffFlow:
    def __init__(self, event_store: EventStore | None = None):
        self._store = event_store or EventStore()
        self._lock = RLock()
        self._idem: dict[str, Receipt] = {}
        self._ledger = InventoryLedger()
        self._audit = AuditTrail()
        self._views: dict[str, _StreamView] = {}
        self._last_at: datetime | None = None
        self._bootstrap()

    # ---------------------------------------------------------------- boot

    def _bootstrap(self) -> None:
        ordered = self._ordered_events()
        for fe in ordered:
            self._fold(fe, replay=True)
        self._rebuild_global_audit()
        # Idempotency keys live on the events themselves, so deduplication
        # survives a full replay: rebuild the recorded-command index.
        for fe in ordered:
            key = fe.payload.get("idempotency_key")
            if key and key not in self._idem:
                self._idem[key] = Receipt(
                    fe.stream, fe.sequence, fe.kind, fe.at, key, False,
                    fe.digest, fe.payload.get("_command_fingerprint", ""),
                    fe.payload.get("_manifest_digest"))

    def _ordered_events(self) -> list[FlowEvent]:
        decoded: list[FlowEvent] = []
        for stream in self._store.all_streams():
            decoded.extend(FlowEvent.decode(e) for e in self._store.read(stream))
        decoded.sort(key=lambda e: (e.at.astimezone(timezone.utc), e.stream, e.sequence))
        return decoded

    def _rebuild_global_audit(self) -> None:
        # Project the hash-chained audit trail in canonical event order so a
        # replay produces byte-identical audit records regardless of the order
        # in which commands happened to arrive.
        self._audit = self._project_audit(self._ordered_events())

    @staticmethod
    def _project_audit(events: Iterable[FlowEvent]) -> AuditTrail:
        trail = AuditTrail()
        for fe in events:
            trail.append(fe.actor, fe.kind, fe.digest, fe.at)
        return trail

    @classmethod
    def replay(cls, event_store: EventStore) -> "HandoffFlow":
        """Rebuild an identical flow from its event log."""
        return cls(event_store)

    # --------------------------------------------------------------- commit

    def _submit(self, stream: str, kind: str, at: datetime, actor: str,
                payload: dict, idempotency_key: str,
                expected_revision: int | None = None) -> Receipt:
        if not idempotency_key:
            raise ValueError("idempotency key required")
        at = at.astimezone(timezone.utc)
        payload = dict(payload)
        payload["idempotency_key"] = idempotency_key
        cmd_fp = command_fingerprint(stream, kind, at, actor, payload)
        payload["_command_fingerprint"] = cmd_fp
        with self._lock:
            prior = self._idem.get(idempotency_key)
            view = self._views.get(stream)
            revision = view.revision if view else 0
            previous = GENESIS if view is None else self._head_digest(stream)
            payload["_command_fingerprint"] = cmd_fp
            if prior is not None:
                if (prior.stream != stream or prior.kind != kind
                        or prior.command_fingerprint != cmd_fp):
                    raise ValueError("idempotency key reused with a different command")
                # Same command resent: return the recorded result without
                # re-running business rules (which would now reject it).
                return replace(prior, at=at, duplicate=True)
            event_digest = FlowEvent.digest(
                stream, revision + 1, kind, at, actor, payload, previous)
            if expected_revision is not None and expected_revision != revision:
                raise RuntimeError("optimistic concurrency conflict")
            if self._last_at is not None and at < self._last_at:
                raise ValueError("event time moved backward")
            candidate = FlowEvent(
                stream, revision + 1, kind, at, actor, dict(payload),
                previous, event_digest,
            )
            self._validate(candidate, view)
            stored = self._store.append(stream, revision, kind, candidate.encode_payload())
            fe = FlowEvent.decode(stored)
            self._fold(fe, replay=False)
            self._rebuild_global_audit()
            manifest = fe.payload.get("_manifest_digest")
            receipt = Receipt(stream, fe.sequence, kind, at, idempotency_key, False,
                              fe.digest, cmd_fp, manifest)
            self._idem[idempotency_key] = receipt
            return receipt

    def _head_digest(self, stream: str) -> str:
        view = self._views.get(stream)
        return GENESIS if view is None else view.head

    # ------------------------------------------------------------- folding

    def _fold(self, fe: FlowEvent, replay: bool) -> None:
        view = self._views.setdefault(fe.stream, _StreamView())
        self._check_chain(fe, view)
        if replay:
            self._validate(fe, view)
        view.audits.append(fe.actor, fe.kind, fe.digest, fe.at)
        if fe.stream.startswith(HANDOFF_STREAM):
            self._fold_handoff(fe, view)
        elif fe.stream.startswith(ACCOUNT_STREAM):
            self._post_stock(fe)
        else:  # pragma: no cover - every stored stream is prefixed
            raise ValueError("unknown stream namespace")
        view.revision = fe.sequence
        view.head = fe.digest
        self._last_at = fe.at

    def _check_chain(self, fe: FlowEvent, view: _StreamView) -> None:
        if fe.previous != view.head:
            raise ValueError("event chain discontinuity")
        if fe.digest != FlowEvent.digest(
                fe.stream, fe.sequence, fe.kind, fe.at, fe.actor, fe.payload, fe.previous):
            raise ValueError("event digest mismatch")
        if fe.sequence != view.revision + 1:
            raise ValueError("sequence gap")

    def _fold_handoff(self, fe: FlowEvent, view: _StreamView) -> None:
        p = fe.payload
        state = view.state
        if fe.kind == "created":
            if state is not None:
                raise ValueError("handoff already created")
            state = HandoffState(
                fe.stream.removeprefix(HANDOFF_STREAM), revision=1,
                created_event=fe.sequence, creator=p["creator"], witness=p["witness"],
                drug_code=p["drug_code"], quantity=Decimal(str(p["quantity"])),
                from_location=p["from_location"], to_location=p["to_location"],
            )
        else:
            if state is None:
                raise ValueError("unknown handoff")

        if fe.kind == "credential_attested":
            cred = Credential(p["holder"], p["credential_id"],
                              datetime.fromisoformat(p["issued_at"]), fe.at,
                              p.get("credential_digest", ""))
            if any(c.credential_id == cred.credential_id for c in state.credentials):
                raise ValueError("duplicate credential attestation")
            state = replace(state, revision=fe.sequence, credentials=state.credentials + (cred,))

        elif fe.kind == "signed":
            role, actor, ref = p["role"], fe.actor, p["signature_ref"]
            if actor not in (state.creator, state.witness):
                raise ValueError("signer is not a handoff party")
            expected = CREATOR if actor == state.creator else WITNESS
            if role != expected:
                raise ValueError("signer role does not match party")
            if state.role_signed(role):
                raise ValueError("role already signed")
            if not ref:
                raise ValueError("signature reference required")
            state = replace(state, revision=fe.sequence,
                            signatures=state.signatures + ((role, actor, ref, fe.at),))

        elif fe.kind == "sealed":
            if state.status == "sealed":
                raise ValueError("handoff already sealed")
            # Sealing books the custody transfer on the inventory ledger; the
            # manifest is captured over the balances *after* booking.
            self._book_transfer(state, fe.sequence)
            manifest = self._build_manifest(fe, state, "initial", "sealed",
                                            len(state.manifests) + 1, None, p["reason"])
            if manifest.digest != p["_manifest_digest"]:
                raise ValueError("sealed manifest digest mismatch")
            state = replace(state, revision=fe.sequence, status="sealed",
                            manifests=state.manifests + (manifest,))

        elif fe.kind == "corrected":
            if state.status != "sealed":
                raise ValueError("corrections require a sealed handoff")
            previous_manifest = state.manifests[-1]
            if p["previous_manifest"] != previous_manifest.digest:
                raise ValueError("correction must extend the latest sealed manifest")
            if p["previous_event_digest"] != fe.previous:
                raise ValueError("correction anchors to the wrong event")
            entries = self._compensation(fe, state, p)
            for entry in entries:
                self._ledger.post(entry[0], entry[1], entry[2], entry[3])
                if self._ledger.balance(entry[0]) < 0:
                    raise ValueError("correction drives account balance negative")
            manifest = self._build_manifest(
                fe, state, "correction", "corrected", len(state.manifests) + 1,
                previous_manifest.digest, p["reason"])
            if manifest.digest != p["_manifest_digest"]:
                raise ValueError("correction manifest digest mismatch")
            state = replace(state, revision=fe.sequence,
                            manifests=state.manifests + (manifest,))

        elif fe.kind not in ("created",):
            raise ValueError("unknown event kind")

        view.state = state

    def _post_stock(self, fe: FlowEvent) -> None:
        if fe.kind != "stock_received":
            raise ValueError("account streams accept only stock_received events")
        p = fe.payload
        account, qty = p["account"], Decimal(str(p["quantity"]))
        if not account or qty <= 0:
            raise ValueError("account and positive quantity required")
        ref = f"{fe.stream.removeprefix(ACCOUNT_STREAM)}:{fe.sequence}"
        try:
            self._ledger.post(account, ref, qty, "controlled receipt")
        except ValueError as exc:
            raise ValueError(str(exc)) from None
        if self._ledger.balance(account) < 0:  # pragma: no cover - receipt only credits
            raise ValueError("account balance negative")

    # ------------------------------------------------------------ builders

    def _build_manifest(self, fe: FlowEvent, state: HandoffState,
                        manifest_type: str, kind: str, seq: int,
                        previous_manifest: str | None, reason: str) -> Manifest:
        balances = {a: self._ledger.balance(a) for a in self._accounts()}
        return Manifest.build(
            state.handoff_id, manifest_type, seq, fe.at, state.creator, state.witness,
            kind, fe.sequence, previous_manifest, fe.previous, reason,
            fe.digest, balances,
        )

    def _accounts(self) -> list[str]:
        rows = self._ledger.entries()
        return sorted({r.account for r in rows})

    def _book_transfer(self, state: HandoffState, sequence: int) -> None:
        base = f"handoff:{state.handoff_id}:seal:{sequence}"
        self._ledger.post(state.from_location, base + ":debit", -state.quantity,
                          f"sealed handoff {state.handoff_id}")
        self._ledger.post(state.to_location, base + ":credit", state.quantity,
                          f"sealed handoff {state.handoff_id}")

    @staticmethod
    def _compensation(fe: FlowEvent, state: HandoffState,
                      p: dict) -> list[tuple[str, str, Decimal, str]]:
        delta = Decimal(str(p["quantity_delta"]))
        if delta == 0:
            raise ValueError("zero correction delta")
        base = f"handoff:{state.handoff_id}:correction:{fe.sequence}"
        reason = f"correction:{state.handoff_id}:{p['reason']}"
        if delta < 0:
            return [(state.to_location, base, delta, reason)]
        return [(state.from_location, base + ":debit", -delta, reason),
                (state.to_location, base + ":credit", delta, reason)]

    # ---------------------------------------------------------- validators

    def _validate(self, fe: FlowEvent, view: _StreamView | None) -> None:
        p = fe.payload
        if fe.kind not in KINDS:
            raise ValueError("unknown event kind")
        if fe.stream.startswith(ACCOUNT_STREAM):
            return  # structural checks live in _post_stock
        if not fe.stream.startswith(HANDOFF_STREAM):
            raise ValueError("unknown stream namespace")
        state = view.state if view else None

        if fe.kind == "created":
            if state is not None:
                raise ValueError("handoff already created")
            if not p.get("creator") or not p.get("witness") or p["creator"] == p["witness"]:
                raise ValueError("two distinct parties required")
            if Decimal(str(p["quantity"])) <= 0:
                raise ValueError("quantity must be positive")
            if not p.get("drug_code") or not p.get("from_location") or not p.get("to_location"):
                raise ValueError("drug code and both locations required")
            return

        if state is None:
            raise ValueError("unknown handoff")

        if fe.kind == "credential_attested":
            if p["holder"] not in (state.creator, state.witness):
                raise ValueError("credential holder is not a handoff party")
            if not p.get("credential_id"):
                raise ValueError("credential id required")
            issued = datetime.fromisoformat(p["issued_at"]).astimezone(timezone.utc)
            if issued > fe.at:
                raise ValueError("credential issued in the future")
            if any(c.credential_id == p["credential_id"] for c in state.credentials):
                raise ValueError("duplicate credential attestation")

        elif fe.kind == "signed":
            if p["role"] not in ROLES:
                raise ValueError("role must be creator or witness")
            if fe.actor not in (state.creator, state.witness):
                raise ValueError("signer is not a handoff party")
            expected = CREATOR if fe.actor == state.creator else WITNESS
            if p["role"] != expected:
                raise ValueError("signer role does not match party")
            if state.role_signed(p["role"]):
                raise ValueError("role already signed")
            if not p.get("signature_ref"):
                raise ValueError("signature reference required")

        elif fe.kind == "sealed":
            if state.status == "sealed":
                raise ValueError("handoff already sealed")
            if fe.actor not in (state.creator, state.witness):
                raise ValueError("sealing must be performed by a handoff party")
            if not state.dual_signed():
                raise ValueError("dual signature required to seal")
            if not state.credentials_complete():
                raise ValueError("both parties must have attested offline credentials")
            if self._ledger.balance(state.from_location) < state.quantity:
                raise ValueError("insufficient inventory at source")
            if not p.get("reason"):
                raise ValueError("seal reason required")

        elif fe.kind == "corrected":
            if state.status != "sealed":
                raise ValueError("corrections require a sealed handoff")
            if fe.actor not in (state.creator, state.witness):
                raise ValueError("correction must be performed by a handoff party")
            if not state.dual_signed():
                raise ValueError("correction requires the dual sign-off on record")
            if p.get("previous_manifest") != state.manifests[-1].digest:
                raise ValueError("correction must extend the latest sealed manifest")
            if not p.get("reason"):
                raise ValueError("correction reason required")
            delta = Decimal(str(p["quantity_delta"]))
            if delta == 0:
                raise ValueError("zero correction delta")
            if delta < 0 and self._ledger.balance(state.to_location) + delta < 0:
                raise ValueError("correction drives destination balance negative")
            if delta > 0 and self._ledger.balance(state.from_location) - delta < 0:
                raise ValueError("correction drives source balance negative")

    # ------------------------------------------------------------ commands

    def open_handoff(self, handoff_id: str, creator: str, witness: str, drug_code: str,
                     quantity, from_location: str, to_location: str, at: datetime,
                     idempotency_key: str) -> Receipt:
        payload = {
            "creator": creator, "witness": witness, "drug_code": drug_code,
            "quantity": str(Decimal(str(quantity))),
            "from_location": from_location, "to_location": to_location,
        }
        return self._submit(HANDOFF_STREAM + handoff_id, "created", at, creator,
                            payload, idempotency_key, expected_revision=0)

    def attest_credential(self, handoff_id: str, holder: str, credential_id: str,
                          issued_at: datetime, at: datetime, idempotency_key: str,
                          credential_digest: str = "") -> Receipt:
        payload = {
            "holder": holder, "credential_id": credential_id,
            "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
            "credential_digest": credential_digest,
        }
        return self._submit(HANDOFF_STREAM + handoff_id, "credential_attested", at, holder,
                            payload, idempotency_key)

    def sign(self, handoff_id: str, actor: str, role: str, signature_ref: str,
             at: datetime, idempotency_key: str) -> Receipt:
        return self._submit(HANDOFF_STREAM + handoff_id, "signed", at, actor,
                            {"role": role, "signature_ref": signature_ref}, idempotency_key)

    def receive_stock(self, account: str, batch_ref: str, quantity, at: datetime,
                      actor: str, idempotency_key: str) -> Receipt:
        return self._submit(ACCOUNT_STREAM + batch_ref, "stock_received", at, actor,
                            {"account": account, "quantity": str(Decimal(str(quantity)))},
                            idempotency_key, expected_revision=0)

    def seal(self, handoff_id: str, actor: str, at: datetime, reason: str,
             idempotency_key: str) -> Receipt:
        # Precompute the evidence manifest deterministically so the digest is
        # captured inside the event itself; the fold re-books the transfer,
        # rebuilds the manifest and cross-checks it. Underscore projection
        # fields are excluded from the event hash, so the pending digest does
        # not feed back into itself.
        with self._lock:
            prior = self._idem.get(idempotency_key)
            if prior is not None:
                if prior.stream != HANDOFF_STREAM + handoff_id or prior.kind != "sealed":
                    raise ValueError("idempotency key reused with a different command")
                return replace(prior, at=at.astimezone(timezone.utc), duplicate=True)
            view = self._views[HANDOFF_STREAM + handoff_id]
            state = view.state
            if state is None:
                raise ValueError("unknown handoff")
            head = self._head_digest(HANDOFF_STREAM + handoff_id)
            logical = {
                "reason": reason, "previous_manifest": None,
                "previous_event_digest": head, "idempotency_key": idempotency_key,
            }
            event_digest = FlowEvent.digest(
                HANDOFF_STREAM + handoff_id, view.revision + 1, "sealed",
                at.astimezone(timezone.utc), actor, logical, head)
            balances = {a: self._ledger.balance(a) for a in self._accounts()}
            balances[state.from_location] = balances.get(state.from_location, Decimal(0)) - state.quantity
            balances[state.to_location] = balances.get(state.to_location, Decimal(0)) + state.quantity
            manifest_preview = Manifest.build(
                handoff_id, "initial", len(state.manifests) + 1,
                at.astimezone(timezone.utc), state.creator, state.witness, "sealed",
                view.revision + 1, None, head, reason, event_digest, balances,
            )
        return self._submit(HANDOFF_STREAM + handoff_id, "sealed", at, actor,
                            {"reason": reason, "previous_manifest": None,
                             "previous_event_digest": head,
                             "_manifest_digest": manifest_preview.digest},
                            idempotency_key)

    def correct(self, handoff_id: str, actor: str, at: datetime, reason: str,
                quantity_delta, idempotency_key: str) -> Receipt:
        with self._lock:
            prior = self._idem.get(idempotency_key)
            if prior is not None:
                if prior.stream != HANDOFF_STREAM + handoff_id or prior.kind != "corrected":
                    raise ValueError("idempotency key reused with a different command")
                return replace(prior, at=at.astimezone(timezone.utc), duplicate=True)
            view = self._views[HANDOFF_STREAM + handoff_id]
            state = view.state
            if state is None:
                raise ValueError("unknown handoff")
            if not state.manifests:
                raise ValueError("corrections require a sealed handoff")
            head = self._head_digest(HANDOFF_STREAM + handoff_id)
            delta = Decimal(str(quantity_delta))
            logical = {
                "reason": reason, "quantity_delta": str(delta),
                "previous_manifest": state.manifests[-1].digest,
                "previous_event_digest": head, "idempotency_key": idempotency_key,
            }
            event_digest = FlowEvent.digest(
                HANDOFF_STREAM + handoff_id, view.revision + 1, "corrected",
                at.astimezone(timezone.utc), actor, logical, head)
            # Preview balances exactly as the compensating entries will book them.
            balances = {a: self._ledger.balance(a) for a in self._accounts()}
            if delta < 0:
                balances[state.to_location] = balances.get(state.to_location, Decimal(0)) + delta
            else:
                balances[state.from_location] = balances.get(state.from_location, Decimal(0)) - delta
                balances[state.to_location] = balances.get(state.to_location, Decimal(0)) + delta
            manifest_preview = Manifest.build(
                handoff_id, "correction", len(state.manifests) + 1,
                at.astimezone(timezone.utc), state.creator, state.witness, "corrected",
                view.revision + 1, state.manifests[-1].digest, head, reason,
                event_digest, balances,
            )
        return self._submit(HANDOFF_STREAM + handoff_id, "corrected", at, actor,
                            {"reason": reason, "quantity_delta": str(delta),
                             "previous_manifest": logical["previous_manifest"],
                             "previous_event_digest": head,
                             "_manifest_digest": manifest_preview.digest},
                            idempotency_key)

    # -------------------------------------------------------------- queries

    def state(self, handoff_id: str) -> HandoffState:
        with self._lock:
            view = self._views.get(HANDOFF_STREAM + handoff_id)
            if view is None or view.state is None:
                raise KeyError(handoff_id)
            return view.state

    def manifest(self, handoff_id: str) -> Manifest:
        return self.state(handoff_id).manifests[-1]

    def manifests(self, handoff_id: str) -> tuple[Manifest, ...]:
        return self.state(handoff_id).manifests

    def balance(self, account: str) -> Decimal:
        with self._lock:
            return self._ledger.balance(account)

    def ledger(self) -> InventoryLedger:
        return self._ledger

    def audit_trail(self) -> AuditTrail:
        return self._audit

    def event_stream(self, handoff_id: str) -> tuple[FlowEvent, ...]:
        with self._lock:
            return tuple(FlowEvent.decode(e)
                         for e in self._store.read(HANDOFF_STREAM + handoff_id))

    # ------------------------------------------------------------- verify

    def verify_all(self) -> dict:
        """Replay the whole log into fresh projections and compare.

        This is independent evidence: the ledger, audit trail and manifests are
        rebuilt by folding the stored events from scratch, rather than trusting
        the live projections that were mutated by the commands.
        """
        ordered = self._ordered_events()
        rebuilt = HandoffFlow(EventStore())
        for fe in ordered:
            rebuilt._fold(fe, replay=True)
        rebuilt._audit = self._project_audit(ordered)
        if not rebuilt._audit.verify() or not self._audit.verify():
            raise ValueError("audit chain broken")
        if len(rebuilt._audit.records) != len(self._audit.records):
            raise ValueError("replayed audit length mismatch")
        for a, b in zip(rebuilt._audit.records, self._audit.records):
            if a.digest != b.digest:
                raise ValueError("replayed audit digest mismatch")
        accounts = set(self._accounts()) | {
            r.account for r in rebuilt._ledger.entries()}
        for account in sorted(accounts):
            if rebuilt._ledger.balance(account) != self._ledger.balance(account):
                raise ValueError("replayed ledger balance mismatch")
        for stream, view in self._views.items():
            if not stream.startswith(HANDOFF_STREAM) or view.state is None:
                continue
            rebuilt_view = rebuilt._views[stream]
            if rebuilt_view.state is None:
                raise ValueError("handoff missing from replay")
            for m1, m2 in zip(view.state.manifests, rebuilt_view.state.manifests):
                if m1.digest != m2.digest:
                    raise ValueError("sealed evidence diverged on replay")
            self._verify_manifest_chain(rebuilt_view.state)
        return {
            "streams": len(self._views),
            "events": len(ordered),
            "manifests": sum(
                len(v.state.manifests) for v in self._views.values()
                if v.state is not None),
            "audit_digest": self._audit.records[-1].digest if self._audit.records else GENESIS,
        }

    @staticmethod
    def _verify_manifest_chain(state: HandoffState) -> None:
        previous = None
        for i, m in enumerate(state.manifests, start=1):
            if m.manifest_seq != i:
                raise ValueError("manifest sequence gap")
            if i == 1 and m.manifest_type != "initial":
                raise ValueError("evidence chain must start with an initial manifest")
            if i > 1 and m.manifest_type != "correction":
                raise ValueError("later manifests must be corrections")
            if m.previous_manifest != previous:
                raise ValueError("manifest chain broken")
            previous = m.digest

    def verify(self, handoff_id: str) -> dict:
        summary = self.verify_all()
        state = self.state(handoff_id)
        self._verify_manifest_chain(state)
        summary["handoff"] = handoff_id
        summary["latest_manifest"] = state.manifests[-1].digest
        return summary
