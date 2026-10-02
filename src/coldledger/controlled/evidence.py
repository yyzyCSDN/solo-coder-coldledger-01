"""Canonical fingerprinting and sealed-evidence manifests for controlled handoffs.

Evidence is sealed over canonical JSON so the same facts always produce the same
digest, which makes the whole flow replayable byte-for-byte. Later corrections
never rewrite a sealed manifest: they seal a new manifest that references the
previous one, forming an append-only evidence chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json


def normalize(value):
    """Coerce timestamps/Decimals and sort object keys for canonical encoding."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {k: normalize(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    return value


def canonical(value) -> str:
    return json.dumps(normalize(value), separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def fingerprint(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Manifest:
    """Sealed evidence bundle for one handoff (initial or correction)."""

    handoff_id: str
    manifest_type: str  # 'initial' | 'correction'
    manifest_seq: int
    sealed_at: datetime
    creator: str
    witness: str
    kind: str  # 'sealed' | 'corrected'
    event_sequence: int
    previous_manifest: str | None
    previous_event_digest: str | None
    reason: str
    head_audit_digest: str
    balances: tuple[tuple[str, str], ...]
    digest: str = field(default="", compare=False)

    @staticmethod
    def build(
        handoff_id: str,
        manifest_type: str,
        manifest_seq: int,
        sealed_at: datetime,
        creator: str,
        witness: str,
        kind: str,
        event_sequence: int,
        previous_manifest: str | None,
        previous_event_digest: str | None,
        reason: str,
        head_audit_digest: str,
        balances: dict[str, Decimal],
    ) -> "Manifest":
        if manifest_type not in ("initial", "correction"):
            raise ValueError("manifest_type must be initial or correction")
        rows = tuple(sorted((a, str(q)) for a, q in balances.items()))
        m = Manifest(
            handoff_id, manifest_type, manifest_seq, sealed_at, creator, witness, kind,
            event_sequence, previous_manifest, previous_event_digest, reason,
            head_audit_digest, rows,
        )
        return replace(m, digest=m._digest())

    def _digest(self) -> str:
        return fingerprint([
            self.handoff_id, self.manifest_type, self.manifest_seq, self.sealed_at,
            self.creator, self.witness, self.kind, self.event_sequence,
            self.previous_manifest, self.previous_event_digest, self.reason,
            self.head_audit_digest, list(self.balances),
        ])

    def as_dict(self) -> dict:
        return {
            "handoff_id": self.handoff_id,
            "manifest_type": self.manifest_type,
            "manifest_seq": self.manifest_seq,
            "sealed_at": self.sealed_at,
            "creator": self.creator,
            "witness": self.witness,
            "kind": self.kind,
            "event_sequence": self.event_sequence,
            "previous_manifest": self.previous_manifest,
            "previous_event_digest": self.previous_event_digest,
            "reason": self.reason,
            "head_audit_digest": self.head_audit_digest,
            "balances": [list(b) for b in self.balances],
            "digest": self.digest,
        }
