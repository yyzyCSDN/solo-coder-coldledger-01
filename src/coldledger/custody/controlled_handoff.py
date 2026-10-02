from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from threading import RLock
from types import MappingProxyType
from typing import Any, Iterable

from ..audit.trail import AuditTrail
from ..core.canonical import canonical, canonical_digest
from ..inventory.ledger import InventoryLedger
from .offline_credentials import OfflineCredential, OfflineCredentialAuthority, OfflineSignature

GENESIS = "GENESIS"
EVENT_DOMAIN = "coldledger.controlled-handoff"


def _utc(value: datetime, name: str = "at") -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _non_empty(value: str, name: str) -> str:
    if not value:
        raise ValueError(f"{name} required")
    return value


def _quantity(value: Any) -> Decimal:
    q = Decimal(str(value))
    if q <= 0:
        raise ValueError("quantity must be positive")
    return q


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class Terms:
    handoff_id: str
    sku: str
    product_name: str
    quantity: Decimal
    unit: str
    source_account: str
    target_account: str
    from_party: str
    to_party: str
    seal: str
    at: datetime

    def validate(self) -> None:
        for name, value in (
            ("handoff_id", self.handoff_id),
            ("sku", self.sku),
            ("product_name", self.product_name),
            ("unit", self.unit),
            ("source_account", self.source_account),
            ("target_account", self.target_account),
            ("from_party", self.from_party),
            ("to_party", self.to_party),
            ("seal", self.seal),
        ):
            _non_empty(value, name)
        _quantity(self.quantity)
        _utc(self.at, "at")
        if self.source_account == self.target_account:
            raise ValueError("source and target inventory accounts must differ")
        if self.from_party == self.to_party:
            raise ValueError("handover parties must differ")


@dataclass(frozen=True)
class CredentialAttestation:
    credential_id: str
    party: str
    at: datetime
    message_digest: str
    digest: str

    @classmethod
    def from_signature(cls, signature: OfflineSignature) -> "CredentialAttestation":
        return cls(
            signature.credential_id,
            signature.party,
            signature.at,
            signature.message_digest,
            signature.digest,
        )

    def matches(self, signature: OfflineSignature) -> bool:
        return (
            self.credential_id == signature.credential_id
            and self.party == signature.party
            and self.at == signature.at
            and self.message_digest == signature.message_digest
            and self.digest == signature.digest
        )


@dataclass(frozen=True)
class ControlledHandoffEvent:
    sequence: int
    stream: str
    revision: int
    kind: str
    at: datetime
    payload: Mapping[str, Any]
    previous: str
    digest: str


@dataclass(frozen=True)
class SealedHandoffEvidence:
    handoff_id: str
    sealed_event_sequence: int
    revision: int
    terms: Terms
    attestations: tuple[CredentialAttestation, CredentialAttestation]
    sealed_at: datetime
    actor: str
    inventory_references: tuple[str, str] | None
    digest: str


@dataclass(frozen=True)
class ControlledHandoff:
    terms: Terms
    status: str
    revision: int
    signatures: dict[str, CredentialAttestation] = field(default_factory=dict)
    addenda: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    updated_at: datetime | None = None
    sealed_at: datetime | None = None
    sealed_evidence_digest: str | None = None
    sealed_event_sequence: int = 0
    sealed_revision: int = 0
    inventory_references: tuple[str, str] | None = None
    reversal_references: tuple[str, str] | None = None
    reversed_at: datetime | None = None

    @property
    def evidence(self) -> SealedHandoffEvidence | None:
        if self.sealed_evidence_digest is None or self.sealed_at is None:
            return None
        return SealedHandoffEvidence(
            self.terms.handoff_id,
            self.sealed_event_sequence,
            self.sealed_revision or self.revision,
            self.terms,
            (self.signatures["from"], self.signatures["to"]),
            self.sealed_at,
            "",
            self.inventory_references,
            self.sealed_evidence_digest,
        )


@dataclass(frozen=True)
class HandoffCommandReceipt:
    command_id: str
    method: str
    request_digest: str
    event: ControlledHandoffEvent
    status: str
    evidence: SealedHandoffEvidence | None


@dataclass(frozen=True)
class _StoredCommand:
    command_id: str
    method: str
    request_digest: str
    event: ControlledHandoffEvent


class ControlledHandoffWorkflow:
    """Append-only coordinator for controlled-drug custody, inventory and audit evidence."""

    def __init__(
        self,
        inventory: InventoryLedger | None = None,
        audit: AuditTrail | None = None,
        authority: OfflineCredentialAuthority | None = None,
    ):
        self.inventory = inventory
        self.audit = audit if audit is not None else AuditTrail()
        self.authority = authority
        self._events: list[ControlledHandoffEvent] = []
        self._states: dict[str, ControlledHandoff] = {}
        self._commands: dict[str, _StoredCommand] = {}
        self._seals: set[str] = set()
        self._lock = RLock()

    @staticmethod
    def terms_digest(terms: Terms) -> str:
        return canonical_digest(["controlled-handoff-terms", terms])

    @staticmethod
    def reversal_digest(handoff_id: str, original_digest: str, reason: str, at: datetime) -> str:
        return canonical_digest([
            "controlled-handoff-reversal",
            handoff_id,
            original_digest,
            reason,
            _utc(at, "at"),
        ])

    @staticmethod
    def addendum_digest(
        handoff_id: str,
        original_digest: str,
        addendum_id: str,
        body: str,
        at: datetime,
    ) -> str:
        return canonical_digest([
            "controlled-handoff-addendum",
            handoff_id,
            original_digest,
            addendum_id,
            body,
            _utc(at, "at"),
        ])

    def begin_handoff(
        self,
        terms: Terms,
        command_id: str,
        actor: str | None = None,
    ) -> HandoffCommandReceipt:
        terms.validate()
        actor = actor or terms.from_party
        _non_empty(actor, "actor")
        at = _utc(terms.at, "terms.at")
        terms = replace(terms, quantity=Decimal(str(terms.quantity)), at=at)
        request = self._fingerprint(
            "begin",
            command_id,
            {"terms": terms, "actor": actor},
        )
        with self._lock:
            existing_command = self._same_command(command_id, "begin", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            existing = self._states.get(terms.handoff_id)
            if existing is not None:
                if existing.terms == terms:
                    event = self._event_for(terms.handoff_id, existing.revision, "handoff.begun")
                    if event is not None:
                        stored = self._store_command(command_id, "begin", request, event)
                        return self._receipt(stored)
                raise ValueError("handoff id already used with different terms")
            if terms.seal in self._seals:
                raise ValueError("seal already used by another handoff")
            payload = {
                "terms": asdict(terms),
                "actor": actor,
                "request_digest": request,
            }
            return self._commit("begin", command_id, request, terms.handoff_id, "handoff.begun", at, payload)

    def sign_terms(
        self,
        handoff_id: str,
        credential: OfflineCredential,
        signature: OfflineSignature,
        command_id: str,
        actor: str | None = None,
    ) -> HandoffCommandReceipt:
        actor = actor or signature.party
        at = _utc(signature.at, "signature.at")
        signature = replace(signature, at=at)
        attestation = CredentialAttestation.from_signature(signature)
        request = self._fingerprint(
            "sign",
            command_id,
            {
                "handoff_id": handoff_id,
                "actor": actor,
                "attestation": attestation,
            },
        )
        with self._lock:
            existing_command = self._same_command(command_id, "sign", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            state = self._require(handoff_id)
            if state.status != "pending":
                if state.signatures.get("from" if signature.party == state.terms.from_party else "to"):
                    previous = self._find_event(handoff_id, "terms.signed", attestation)
                    if previous is not None:
                        stored = self._store_command(command_id, "sign", request, previous)
                        return self._receipt(stored)
                raise ValueError("terms can only be signed before sealing")
            side = self._signature_side(state, signature)
            current = state.signatures.get(side)
            if current is not None:
                if current == attestation:
                    previous = self._find_event(handoff_id, "terms.signed", attestation)
                    if previous is None:
                        raise RuntimeError("signature state without event")
                    stored = self._store_command(command_id, "sign", request, previous)
                    return self._receipt(stored)
                raise ValueError(f"{side} party already signed with a different offline credential")
            self._verify_attestation(state.terms, credential, signature, state.terms.from_party if side == "from" else state.terms.to_party)
            payload = {
                "attestation": asdict(attestation),
                "actor": actor,
                "request_digest": request,
            }
            return self._commit("sign", command_id, request, handoff_id, "terms.signed", at, payload)

    def seal_handoff(
        self,
        handoff_id: str,
        command_id: str,
        at: datetime,
        actor: str,
    ) -> HandoffCommandReceipt:
        at = _utc(at, "at")
        _non_empty(actor, "actor")
        request = self._fingerprint(
            "seal",
            command_id,
            {"handoff_id": handoff_id, "at": at, "actor": actor},
        )
        with self._lock:
            existing_command = self._same_command(command_id, "seal", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            state = self._require(handoff_id)
            if state.status == "sealed":
                event = self._find_event(handoff_id, "handoff.sealed")
                if event is not None:
                    stored = self._store_command(command_id, "seal", request, event)
                    return self._receipt(stored)
            if state.status != "pending":
                raise ValueError("only pending handoffs can be sealed")
            self._require_dual_signatures(state, self.terms_digest(state.terms), at)
            transfer_refs = None
            if self.inventory is not None:
                self._ensure_inventory_balance(state.terms.source_account, state.terms.quantity)
                reference = f"controlled:{handoff_id}:{state.revision + 1}:transfer"
                debit, credit = self.inventory.transfer(
                    state.terms.source_account,
                    state.terms.target_account,
                    state.terms.quantity,
                    reference,
                    "controlled handoff sealed",
                )
                transfer_refs = (debit.reference, credit.reference)
            payload = {
                "actor": actor,
                "terms_digest": self.terms_digest(state.terms),
                "inventory_references": list(transfer_refs) if transfer_refs else None,
                "request_digest": request,
            }
            return self._commit("seal", command_id, request, handoff_id, "handoff.sealed", at, payload, transfer_refs)

    def cancel_handoff(
        self,
        handoff_id: str,
        command_id: str,
        reason: str,
        at: datetime,
        actor: str,
    ) -> HandoffCommandReceipt:
        at = _utc(at, "at")
        _non_empty(reason, "reason")
        _non_empty(actor, "actor")
        request = self._fingerprint(
            "cancel",
            command_id,
            {"handoff_id": handoff_id, "reason": reason, "at": at, "actor": actor},
        )
        with self._lock:
            existing_command = self._same_command(command_id, "cancel", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            state = self._require(handoff_id)
            if state.status == "cancelled":
                event = self._find_event(handoff_id, "handoff.cancelled")
                if event is not None:
                    stored = self._store_command(command_id, "cancel", request, event)
                    return self._receipt(stored)
            if state.status != "pending":
                raise ValueError("sealed handoffs must be reversed, not cancelled")
            payload = {"reason": reason, "actor": actor, "request_digest": request}
            return self._commit("cancel", command_id, request, handoff_id, "handoff.cancelled", at, payload)

    def reverse_handoff(
        self,
        handoff_id: str,
        command_id: str,
        reason: str,
        at: datetime,
        actor: str,
        from_credential: OfflineCredential,
        from_signature: OfflineSignature,
        to_credential: OfflineCredential,
        to_signature: OfflineSignature,
    ) -> HandoffCommandReceipt:
        at = _utc(at, "at")
        _non_empty(reason, "reason")
        _non_empty(actor, "actor")
        with self._lock:
            state = self._require(handoff_id)
            if state.sealed_evidence_digest is None:
                raise ValueError("only sealed handoffs can be reversed")
            digest = self.reversal_digest(handoff_id, state.sealed_evidence_digest, reason, at)
            from_sig = replace(from_signature, at=_utc(from_signature.at, "from_signature.at"))
            to_sig = replace(to_signature, at=_utc(to_signature.at, "to_signature.at"))
            signatures = {"from": from_sig, "to": to_sig}
            request = self._fingerprint(
                "reverse",
                command_id,
                {
                    "handoff_id": handoff_id,
                    "reason": reason,
                    "at": at,
                    "actor": actor,
                    "from": CredentialAttestation.from_signature(from_sig),
                    "to": CredentialAttestation.from_signature(to_sig),
                },
            )
            existing_command = self._same_command(command_id, "reverse", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            if state.status == "reversed":
                event = self._find_event(handoff_id, "handoff.reversed")
                if event is not None:
                    stored = self._store_command(command_id, "reverse", request, event)
                    return self._receipt(stored)
            if state.status != "sealed":
                raise ValueError("only sealed handoffs can be reversed")
            self._verify_dual_event_signatures(state, digest, at, signatures, from_credential, to_credential)
            reversal_refs = None
            if self.inventory is not None:
                if state.inventory_references is None:
                    raise ValueError("sealed handoff has no inventory entries to reverse")
                self._ensure_inventory_balance(state.terms.target_account, state.terms.quantity)
                reversal_refs = self._reverse_inventory(state, reason)
            payload = {
                "reason": reason,
                "actor": actor,
                "original_digest": state.sealed_evidence_digest,
                "reversal_digest": digest,
                "from": asdict(CredentialAttestation.from_signature(from_sig)),
                "to": asdict(CredentialAttestation.from_signature(to_sig)),
                "inventory_references": list(reversal_refs) if reversal_refs else None,
                "request_digest": request,
            }
            return self._commit("reverse", command_id, request, handoff_id, "handoff.reversed", at, payload)

    def append_addendum(
        self,
        handoff_id: str,
        command_id: str,
        addendum_id: str,
        body: str,
        at: datetime,
        actor: str,
        from_credential: OfflineCredential,
        from_signature: OfflineSignature,
        to_credential: OfflineCredential,
        to_signature: OfflineSignature,
    ) -> HandoffCommandReceipt:
        at = _utc(at, "at")
        _non_empty(addendum_id, "addendum_id")
        _non_empty(body, "body")
        _non_empty(actor, "actor")
        with self._lock:
            state = self._require(handoff_id)
            if state.sealed_evidence_digest is None:
                raise ValueError("addenda can only be appended to sealed evidence")
            existing_addendum = state.addenda.get(addendum_id)
            digest = self.addendum_digest(
                handoff_id,
                state.sealed_evidence_digest,
                addendum_id,
                body,
                at,
            )
            from_sig = replace(from_signature, at=_utc(from_signature.at, "from_signature.at"))
            to_sig = replace(to_signature, at=_utc(to_signature.at, "to_signature.at"))
            signatures = {"from": from_sig, "to": to_sig}
            request = self._fingerprint(
                "addendum",
                command_id,
                {
                    "handoff_id": handoff_id,
                    "addendum_id": addendum_id,
                    "body": body,
                    "at": at,
                    "actor": actor,
                    "from": CredentialAttestation.from_signature(from_sig),
                    "to": CredentialAttestation.from_signature(to_sig),
                },
            )
            existing_command = self._same_command(command_id, "addendum", request)
            if existing_command is not None:
                return self._receipt(existing_command)
            if existing_addendum is not None:
                if existing_addendum["digest"] == digest:
                    event = self._find_addendum_event(handoff_id, addendum_id)
                    if event is not None:
                        stored = self._store_command(command_id, "addendum", request, event)
                        return self._receipt(stored)
                raise ValueError("addendum id already used with different content")
            if state.status != "sealed":
                raise ValueError("addenda cannot be appended after reversal; start a corrective handoff")
            self._verify_dual_event_signatures(state, digest, at, signatures, from_credential, to_credential)
            payload = {
                "addendum_id": addendum_id,
                "body": body,
                "actor": actor,
                "original_digest": state.sealed_evidence_digest,
                "addendum_digest": digest,
                "from": asdict(CredentialAttestation.from_signature(from_sig)),
                "to": asdict(CredentialAttestation.from_signature(to_sig)),
                "request_digest": request,
            }
            return self._commit("addendum", command_id, request, handoff_id, "evidence.addendum_appended", at, payload)

    def get(self, handoff_id: str) -> ControlledHandoff:
        with self._lock:
            state = self._require(handoff_id)
            return replace(state, signatures=dict(state.signatures), addenda=dict(state.addenda))

    def evidence(self, handoff_id: str) -> SealedHandoffEvidence:
        with self._lock:
            state = self._require(handoff_id)
            sealed = self._find_event(handoff_id, "handoff.sealed")
            if sealed is None or state.sealed_evidence_digest is None:
                raise ValueError("handoff is not sealed")
            return self._evidence_for(state, sealed)

    def events(self, handoff_id: str | None = None) -> tuple[ControlledHandoffEvent, ...]:
        with self._lock:
            if handoff_id is None:
                return tuple(self._events)
            return tuple(e for e in self._events if e.stream == handoff_id)

    def command(self, command_id: str) -> HandoffCommandReceipt:
        with self._lock:
            return self._receipt(self._commands[_non_empty(command_id, "command_id")])

    @classmethod
    def replay(
        cls,
        events: Iterable[ControlledHandoffEvent],
        *,
        inventory: InventoryLedger | None = None,
        audit: AuditTrail | None = None,
        authority: OfflineCredentialAuthority | None = None,
        opening_balances: dict[str, Decimal] | None = None,
    ) -> "ControlledHandoffWorkflow":
        workflow = cls(inventory=inventory, audit=audit, authority=authority)
        if opening_balances:
            if workflow.inventory is None:
                workflow.inventory = InventoryLedger()
            for account in sorted(opening_balances):
                amount = Decimal(str(opening_balances[account]))
                if amount:
                    workflow.inventory.post(account, f"controlled:opening:{account}", amount, "replay opening balance")
        previous = GENESIS
        seen_requests: set[str] = set()
        for expected_sequence, event in enumerate(sorted(events, key=lambda item: item.sequence), start=1):
            if event.sequence != expected_sequence:
                raise ValueError("event sequence gap")
            if event.previous != previous:
                raise ValueError("event previous-digest chain broken")
            computed = cls._event_digest(event.sequence, event.stream, event.revision, event.kind, event.at, event.payload, event.previous)
            if event.digest != computed:
                raise ValueError("event digest mismatch")
            event = replace(event, payload=_freeze(dict(event.payload)))
            request_digest = str(event.payload.get("request_digest", ""))
            if request_digest in seen_requests:
                raise ValueError("duplicate request digest in event log")
            seen_requests.add(request_digest)
            workflow._replay_event(event)
            workflow._store_replay_command(event)
            previous = event.digest
        if not workflow.audit.verify():
            raise ValueError("audit trail verification failed")
        return workflow

    def verify(self) -> None:
        with self._lock:
            previous = GENESIS
            for index, event in enumerate(self._events, start=1):
                if event.sequence != index:
                    raise ValueError("event sequence gap")
                if event.previous != previous:
                    raise ValueError("event previous-digest chain broken")
                digest = self._event_digest(event.sequence, event.stream, event.revision, event.kind, event.at, event.payload, event.previous)
                if event.digest != digest:
                    raise ValueError("event digest mismatch")
                previous = digest
            if not self.audit.verify():
                raise ValueError("audit trail verification failed")
            if len(self.audit.records) != len(self._events):
                raise ValueError("audit and event logs are out of sync")
            for event, record in zip(self._events, self.audit.records):
                if record.subject != event.digest:
                    raise ValueError("audit record is not bound to event digest")
            if self.inventory is not None:
                self.inventory.audit()

    def _replay_event(self, event: ControlledHandoffEvent) -> None:
        state = self._states.get(event.stream)
        expected_revision = 0 if state is None else state.revision
        if event.revision != expected_revision + 1:
            raise ValueError("stream revision gap")
        self._validate_event_time(state, event)
        if event.kind == "handoff.begun":
            if state is not None:
                raise ValueError("duplicate begin event")
            terms = self._terms_from_payload(event.payload["terms"])
            if terms.handoff_id != event.stream:
                raise ValueError("event stream mismatch")
            if terms.seal in self._seals:
                raise ValueError("seal reused")
            self._seals.add(terms.seal)
            self._states[event.stream] = ControlledHandoff(terms, "pending", 1, updated_at=event.at)
        elif event.kind == "terms.signed":
            self._require_pending(state, event.stream)
            assert state is not None
            attestation = self._attestation_from_payload(event.payload["attestation"])
            side = self._attestation_side(state.terms, attestation)
            if side in state.signatures:
                raise ValueError("duplicate signature side event")
            credential = self._credential_for_replay(attestation)
            if credential is not None:
                self._verify_attestation(
                    state.terms,
                    credential,
                    self._signature_from_attestation(attestation),
                    attestation.party,
                )
            signatures = dict(state.signatures)
            signatures[side] = attestation
            self._states[event.stream] = replace(state, signatures=signatures, revision=event.revision, updated_at=event.at)
        elif event.kind == "handoff.sealed":
            self._require_pending(state, event.stream)
            assert state is not None
            digest = self.terms_digest(state.terms)
            if event.payload["terms_digest"] != digest:
                raise ValueError("sealed terms digest mismatch")
            self._verify_stored_dual_signatures(state, digest, event.at)
            refs = self._refs_from_payload(event.payload.get("inventory_references"))
            if self.inventory is not None and refs is not None:
                self._ensure_transfer(state.terms, event.revision, refs)
            self._states[event.stream] = replace(
                state,
                status="sealed",
                revision=event.revision,
                updated_at=event.at,
                sealed_at=event.at,
                sealed_evidence_digest=event.digest,
                sealed_event_sequence=event.sequence,
                sealed_revision=event.revision,
                inventory_references=refs,
            )
        elif event.kind == "handoff.cancelled":
            self._require_pending(state, event.stream)
            assert state is not None
            self._states[event.stream] = replace(state, status="cancelled", revision=event.revision, updated_at=event.at)
        elif event.kind == "handoff.reversed":
            if state is None or state.status != "sealed" or state.sealed_evidence_digest is None:
                raise ValueError("reversal event does not follow sealed handoff")
            if event.payload["original_digest"] != state.sealed_evidence_digest:
                raise ValueError("reversal does not bind sealed evidence")
            digest = self.reversal_digest(
                event.stream,
                state.sealed_evidence_digest,
                event.payload["reason"],
                event.at,
            )
            if event.payload["reversal_digest"] != digest:
                raise ValueError("reversal digest mismatch")
            self._verify_stored_dual_payload_signatures(state, digest, event.at, event.payload)
            refs = self._refs_from_payload(event.payload.get("inventory_references"))
            if self.inventory is not None:
                if state.inventory_references is None:
                    raise ValueError("reversal without sealed inventory references")
                self._ensure_reversal(state, event, refs)
            self._states[event.stream] = replace(
                state,
                status="reversed",
                revision=event.revision,
                updated_at=event.at,
                reversed_at=event.at,
                reversal_references=refs,
            )
        elif event.kind == "evidence.addendum_appended":
            if state is None or state.status != "sealed" or state.sealed_evidence_digest is None:
                raise ValueError("addendum event does not follow sealed handoff")
            addendum_id = event.payload["addendum_id"]
            if addendum_id in state.addenda:
                raise ValueError("duplicate addendum event")
            if event.payload["original_digest"] != state.sealed_evidence_digest:
                raise ValueError("addendum does not bind sealed evidence")
            digest = self.addendum_digest(
                event.stream,
                state.sealed_evidence_digest,
                addendum_id,
                event.payload["body"],
                event.at,
            )
            if event.payload["addendum_digest"] != digest:
                raise ValueError("addendum digest mismatch")
            self._verify_stored_dual_payload_signatures(state, digest, event.at, event.payload)
            addenda = dict(state.addenda)
            addenda[addendum_id] = {"body": event.payload["body"], "digest": digest}
            self._states[event.stream] = replace(
                state,
                revision=event.revision,
                updated_at=event.at,
                addenda=addenda,
            )
        else:
            raise ValueError(f"unknown event kind {event.kind}")
        self._append_audit(event)
        self._events.append(event)

    def _store_replay_command(self, event: ControlledHandoffEvent) -> None:
        command_id = str(event.payload.get("command_id", ""))
        if not command_id:
            raise ValueError("replayed event missing command id")
        if command_id in self._commands:
            raise ValueError("command id appears in more than one event")
        method = {
            "handoff.begun": "begin",
            "terms.signed": "sign",
            "handoff.sealed": "seal",
            "handoff.cancelled": "cancel",
            "handoff.reversed": "reverse",
            "evidence.addendum_appended": "addendum",
        }[event.kind]
        request_digest = str(event.payload.get("request_digest", ""))
        self._commands[command_id] = _StoredCommand(command_id, method, request_digest, event)

    def _commit(
        self,
        method: str,
        command_id: str,
        request_digest: str,
        handoff_id: str,
        kind: str,
        at: datetime,
        payload: Mapping[str, Any],
        transfer_refs: tuple[str, str] | None = None,
    ) -> HandoffCommandReceipt:
        state = self._states.get(handoff_id)
        revision = 1 if state is None else state.revision + 1
        event_payload = dict(payload)
        event_payload["command_id"] = command_id
        event = self._make_event(handoff_id, revision, kind, at, event_payload)
        self._apply_live_event(event, transfer_refs)
        self.audit.append("system", kind, event.digest, at=event.at)
        self._events.append(event)
        stored = self._store_command(command_id, method, request_digest, event)
        return self._receipt(stored)

    def _apply_live_event(self, event: ControlledHandoffEvent, transfer_refs: tuple[str, str] | None = None) -> None:
        before = self._states.get(event.stream)
        # All semantic validation happens before inventory side effects in the public command.
        if event.kind == "handoff.begun":
            terms = self._terms_from_payload(event.payload["terms"])
            self._states[event.stream] = ControlledHandoff(terms, "pending", 1, updated_at=event.at)
        elif event.kind == "terms.signed":
            assert before is not None
            attestation = self._attestation_from_payload(event.payload["attestation"])
            side = self._attestation_side(before.terms, attestation)
            signatures = dict(before.signatures)
            signatures[side] = attestation
            self._states[event.stream] = replace(before, signatures=signatures, revision=event.revision, updated_at=event.at)
        elif event.kind == "handoff.sealed":
            assert before is not None
            self._states[event.stream] = replace(
                before,
                status="sealed",
                revision=event.revision,
                updated_at=event.at,
                sealed_at=event.at,
                sealed_evidence_digest=event.digest,
                sealed_event_sequence=event.sequence,
                sealed_revision=event.revision,
                inventory_references=transfer_refs,
            )
        elif event.kind == "handoff.cancelled":
            assert before is not None
            self._states[event.stream] = replace(before, status="cancelled", revision=event.revision, updated_at=event.at)
        elif event.kind == "handoff.reversed":
            assert before is not None
            self._states[event.stream] = replace(
                before,
                status="reversed",
                revision=event.revision,
                updated_at=event.at,
                reversed_at=event.at,
                reversal_references=transfer_refs,
            )
        elif event.kind == "evidence.addendum_appended":
            assert before is not None
            addenda = dict(before.addenda)
            addenda[event.payload["addendum_id"]] = {
                "body": event.payload["body"],
                "digest": event.payload["addendum_digest"],
            }
            self._states[event.stream] = replace(
                before,
                revision=event.revision,
                updated_at=event.at,
                addenda=addenda,
            )
        else:
            raise ValueError(f"unknown event kind {event.kind}")

    def _make_event(self, stream: str, revision: int, kind: str, at: datetime, payload: Mapping[str, Any]) -> ControlledHandoffEvent:
        sequence = len(self._events) + 1
        previous = self._events[-1].digest if self._events else GENESIS
        normalized_payload = canonical(payload)
        stored_payload = _freeze(dict(payload))
        digest = self._event_digest(sequence, stream, revision, kind, at, normalized_payload, previous)
        return ControlledHandoffEvent(sequence, stream, revision, kind, at, stored_payload, previous, digest)

    @staticmethod
    def _event_digest(sequence, stream, revision, kind, at, payload, previous) -> str:
        return canonical_digest([
            EVENT_DOMAIN,
            sequence,
            previous,
            stream,
            revision,
            kind,
            _utc(at, "event.at"),
            payload,
        ])

    def _append_audit(self, event: ControlledHandoffEvent) -> None:
        if len(self.audit.records) >= event.sequence:
            record = self.audit.records[event.sequence - 1]
            if record.subject != event.digest:
                raise ValueError("replayed audit record is not bound to event digest")
            return
        if len(self.audit.records) != event.sequence - 1:
            raise ValueError("audit sequence gap")
        self.audit.append("system", event.kind, event.digest, at=event.at)

    def _ensure_transfer(self, terms: Terms, revision: int, refs: tuple[str, str] | None) -> None:
        assert self.inventory is not None
        if refs is None:
            return
        debit_ref, credit_ref = refs
        rows = self.inventory.entries()
        existing_debit = next((row for row in rows if row.reference == debit_ref), None)
        existing_credit = next((row for row in rows if row.reference == credit_ref), None)
        if existing_debit is not None or existing_credit is not None:
            if existing_debit is None or existing_credit is None:
                raise ValueError("inventory transfer pair is incomplete")
            if existing_debit.account != terms.source_account or existing_credit.account != terms.target_account:
                raise ValueError("inventory transfer accounts do not match sealed terms")
            if existing_debit.quantity != -terms.quantity or existing_credit.quantity != terms.quantity:
                raise ValueError("inventory transfer quantity does not match sealed terms")
            return
        self._ensure_inventory_balance(terms.source_account, terms.quantity)
        reference = f"controlled:{terms.handoff_id}:{revision}:transfer"
        debit, credit = self.inventory.transfer(
            terms.source_account,
            terms.target_account,
            terms.quantity,
            reference,
            "controlled handoff sealed",
        )
        if (debit.reference, credit.reference) != refs:
            raise ValueError("inventory references do not match sealed evidence")

    def _reverse_inventory(self, state: ControlledHandoff, reason: str) -> tuple[str, str]:
        assert self.inventory is not None and state.inventory_references is not None
        debit_ref, credit_ref = state.inventory_references
        rows = self.inventory.entries()
        debit_original = next(row for row in rows if row.reference == debit_ref)
        credit_original = next(row for row in rows if row.reference == credit_ref)
        base = f"controlled:{state.terms.handoff_id}:{state.revision + 1}:reverse"
        credit_reversal = self.inventory.reverse(credit_original.sequence, f"{base}:credit", reason)
        debit_reversal = self.inventory.reverse(debit_original.sequence, f"{base}:debit", reason)
        return debit_reversal.reference, credit_reversal.reference

    def _ensure_reversal(self, state: ControlledHandoff, event: ControlledHandoffEvent, refs: tuple[str, str] | None) -> None:
        assert self.inventory is not None
        debit_ref, credit_ref = state.inventory_references or (None, None)
        if not debit_ref or not credit_ref:
            raise ValueError("missing sealed inventory references")
        rows = self.inventory.entries()
        debit_original = next((row for row in rows if row.reference == debit_ref), None)
        credit_original = next((row for row in rows if row.reference == credit_ref), None)
        if debit_original is None or credit_original is None:
            raise ValueError("original inventory transfer missing")
        desired_debit_rev, desired_credit_rev = refs or (None, None)
        existing_debit = next((row for row in rows if row.reference == desired_debit_rev), None) if desired_debit_rev else None
        existing_credit = next((row for row in rows if row.reference == desired_credit_rev), None) if desired_credit_rev else None
        if existing_debit is not None or existing_credit is not None:
            if existing_debit is None or existing_credit is None:
                raise ValueError("inventory reversal pair is incomplete")
            if existing_debit.quantity != state.terms.quantity or existing_credit.quantity != -state.terms.quantity:
                raise ValueError("inventory reversal quantity mismatch")
            return
        self._ensure_inventory_balance(state.terms.target_account, state.terms.quantity)
        base = f"controlled:{state.terms.handoff_id}:{event.revision}:reverse"
        credit_reversal = self.inventory.reverse(credit_original.sequence, f"{base}:credit", event.payload["reason"])
        debit_reversal = self.inventory.reverse(debit_original.sequence, f"{base}:debit", event.payload["reason"])
        actual = (debit_reversal.reference, credit_reversal.reference)
        if refs is not None and actual != refs:
            raise ValueError("reversal inventory references do not match evidence")

    def _ensure_inventory_balance(self, account: str, quantity: Decimal) -> None:
        assert self.inventory is not None
        if self.inventory.balance(account) < quantity:
            raise ValueError("insufficient inventory balance")

    def _verify_dual_event_signatures(
        self,
        state: ControlledHandoff,
        digest: str,
        at: datetime,
        signatures: dict[str, OfflineSignature],
        from_credential: OfflineCredential,
        to_credential: OfflineCredential,
    ) -> None:
        self._verify_attestation(state.terms, from_credential, signatures["from"], state.terms.from_party, digest, at)
        self._verify_attestation(state.terms, to_credential, signatures["to"], state.terms.to_party, digest, at)

    def _verify_stored_dual_signatures(self, state: ControlledHandoff, digest: str, at: datetime) -> None:
        if set(state.signatures) != {"from", "to"}:
            raise ValueError("dual signatures required")
        for side, party in (("from", state.terms.from_party), ("to", state.terms.to_party)):
            attestation = state.signatures[side]
            credential = self._credential_for_replay(attestation)
            if credential is not None:
                self._verify_attestation(
                    state.terms,
                    credential,
                    self._signature_from_attestation(attestation),
                    party,
                    digest,
                    at,
                )

    def _verify_stored_dual_payload_signatures(self, state: ControlledHandoff, digest: str, at: datetime, payload: dict[str, Any]) -> None:
        for side, party in (("from", state.terms.from_party), ("to", state.terms.to_party)):
            attestation = self._attestation_from_payload(payload[side])
            credential = self._credential_for_replay(attestation)
            if credential is not None:
                self._verify_attestation(
                    state.terms,
                    credential,
                    self._signature_from_attestation(attestation),
                    party,
                    digest,
                    at,
                )

    def _verify_attestation(
        self,
        terms: Terms,
        credential: OfflineCredential,
        signature: OfflineSignature,
        expected_party: str,
        expected_digest: str | None = None,
        event_at: datetime | None = None,
    ) -> None:
        if self.authority is None:
            return
        expected_digest = expected_digest or self.terms_digest(terms)
        self.authority.verify(
            credential,
            expected_digest,
            event_at or signature.at,
            expect_party=expected_party,
            signature=signature,
        )

    def _credential_for_replay(self, attestation: CredentialAttestation) -> OfflineCredential | None:
        if self.authority is None:
            return None
        return self.authority.credential(attestation.credential_id)

    def _require_dual_signatures(self, state: ControlledHandoff, digest: str, at: datetime) -> None:
        if set(state.signatures) != {"from", "to"}:
            raise ValueError("both parties must sign before sealing")
        if self.authority is not None:
            self._verify_stored_dual_signatures(state, digest, at)

    @staticmethod
    def _signature_side(state: ControlledHandoff, signature: OfflineSignature) -> str:
        return ControlledHandoffWorkflow._party_side(state.terms, signature.party)

    @staticmethod
    def _attestation_side(terms: Terms, attestation: CredentialAttestation) -> str:
        return ControlledHandoffWorkflow._party_side(terms, attestation.party)

    @staticmethod
    def _party_side(terms: Terms, party: str) -> str:
        if party == terms.from_party:
            return "from"
        if party == terms.to_party:
            return "to"
        raise ValueError("signature party is not a handover party")

    @staticmethod
    def _signature_from_attestation(attestation: CredentialAttestation) -> OfflineSignature:
        return OfflineSignature(
            attestation.credential_id,
            attestation.party,
            attestation.at,
            attestation.message_digest,
            attestation.digest,
        )

    @staticmethod
    def _attestation_from_payload(payload: dict[str, Any]) -> CredentialAttestation:
        return CredentialAttestation(
            str(payload["credential_id"]),
            str(payload["party"]),
            payload["at"],
            str(payload["message_digest"]),
            str(payload["digest"]),
        )

    @staticmethod
    def _refs_from_payload(value: Any) -> tuple[str, str] | None:
        if value is None:
            return None
        return str(value[0]), str(value[1])

    @staticmethod
    def _terms_from_payload(payload: dict[str, Any]) -> Terms:
        return Terms(
            handoff_id=str(payload["handoff_id"]),
            sku=str(payload["sku"]),
            product_name=str(payload["product_name"]),
            quantity=Decimal(str(payload["quantity"])),
            unit=str(payload["unit"]),
            source_account=str(payload["source_account"]),
            target_account=str(payload["target_account"]),
            from_party=str(payload["from_party"]),
            to_party=str(payload["to_party"]),
            seal=str(payload["seal"]),
            at=payload["at"],
        )

    def _evidence_for(self, state: ControlledHandoff, sealed_event: ControlledHandoffEvent) -> SealedHandoffEvidence:
        if "from" not in state.signatures or "to" not in state.signatures:
            raise ValueError("sealed event missing dual signatures")
        return SealedHandoffEvidence(
            state.terms.handoff_id,
            sealed_event.sequence,
            sealed_event.revision,
            state.terms,
            (state.signatures["from"], state.signatures["to"]),
            state.sealed_at or sealed_event.at,
            str(sealed_event.payload.get("actor", "")),
            state.inventory_references,
            sealed_event.digest,
        )

    def _receipt(self, stored: _StoredCommand) -> HandoffCommandReceipt:
        state = self._states[stored.event.stream]
        status_by_kind = {
            "handoff.begun": "pending",
            "terms.signed": "pending",
            "handoff.sealed": "sealed",
            "handoff.cancelled": "cancelled",
            "handoff.reversed": "reversed",
            "evidence.addendum_appended": "sealed",
        }
        status = status_by_kind[stored.event.kind]
        evidence = None
        if stored.event.kind == "handoff.sealed":
            evidence = self._evidence_for(state, stored.event)
        return HandoffCommandReceipt(
            stored.command_id,
            stored.method,
            stored.request_digest,
            stored.event,
            state.status,
            evidence,
        )

    def _store_command(self, command_id: str, method: str, request_digest: str, event: ControlledHandoffEvent) -> _StoredCommand:
        _non_empty(command_id, "command_id")
        stored = _StoredCommand(command_id, method, request_digest, event)
        self._commands[command_id] = stored
        return stored

    def _same_command(self, command_id: str, method: str, request_digest: str) -> _StoredCommand | None:
        existing = self._commands.get(_non_empty(command_id, "command_id"))
        if existing is None:
            return None
        if existing.method != method or existing.request_digest != request_digest:
            raise RuntimeError("idempotency key reused with a different command")
        return existing

    @staticmethod
    def _fingerprint(method: str, command_id: str, payload: dict[str, Any]) -> str:
        _non_empty(command_id, "command_id")
        return canonical_digest(["controlled-handoff-command", method, command_id, payload])

    def _require(self, handoff_id: str) -> ControlledHandoff:
        state = self._states.get(_non_empty(handoff_id, "handoff_id"))
        if state is None:
            raise KeyError(handoff_id)
        return state

    @staticmethod
    def _require_pending(state: ControlledHandoff | None, handoff_id: str) -> None:
        if state is None:
            raise KeyError(handoff_id)
        if state.status != "pending":
            raise ValueError(f"expected pending handoff, got {state.status}")

    @staticmethod
    def _validate_event_time(state: ControlledHandoff | None, event: ControlledHandoffEvent) -> None:
        if state is not None and state.updated_at is not None and event.at < state.updated_at:
            raise ValueError("event time moved backward")

    def _find_event(self, handoff_id: str, kind: str, attestation: CredentialAttestation | None = None) -> ControlledHandoffEvent | None:
        for event in self._events:
            if event.stream != handoff_id or event.kind != kind:
                continue
            if attestation is None:
                return event
            if self._attestation_from_payload(event.payload["attestation"]) == attestation:
                return event
        return None

    def _find_addendum_event(self, handoff_id: str, addendum_id: str) -> ControlledHandoffEvent | None:
        for event in self._events:
            if event.stream == handoff_id and event.kind == "evidence.addendum_appended" and event.payload["addendum_id"] == addendum_id:
                return event
        return None

    def _event_for(self, handoff_id: str, _revision: int, kind: str) -> ControlledHandoffEvent | None:
        return self._find_event(handoff_id, kind)
