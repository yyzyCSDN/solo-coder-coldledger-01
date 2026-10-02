from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import os

from ..core.canonical import canonical_json

GENESIS = "GENESIS"


def _hmac(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


@dataclass(frozen=True)
class OfflineCredential:
    credential_id: str
    party: str
    issued_to: str
    issued_at: datetime
    expires_at: datetime
    token: str

    def __repr__(self) -> str:
        return (
            f"OfflineCredential(credential_id={self.credential_id!r}, party={self.party!r}, "
            f"issued_to={self.issued_to!r}, issued_at={self.issued_at!r}, "
            f"expires_at={self.expires_at!r}, token='<redacted>')"
        )


@dataclass(frozen=True)
class OfflineSignature:
    credential_id: str
    party: str
    at: datetime
    message_digest: str
    digest: str

    def __repr__(self) -> str:
        return (
            f"OfflineSignature(credential_id={self.credential_id!r}, party={self.party!r}, "
            f"at={self.at!r}, message_digest={self.message_digest!r}, digest='<redacted>')"
        )


class OfflineCredentialAuthority:
    """Deterministic offline credentials backed by HMAC rather than a network service."""

    def __init__(self, secret: bytes | str | None = None, issuer: str = "coldledger"):
        if secret is None:
            secret = os.urandom(32)
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self._secret = bytes(secret)
        self.issuer = issuer
        self._registry: dict[str, OfflineCredential] = {}

    def issue(
        self,
        credential_id: str,
        party: str,
        issued_to: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> OfflineCredential:
        if not credential_id or not party or not issued_to:
            raise ValueError("credential id, party and holder required")
        issued_at = _aware(issued_at, "issued_at")
        expires_at = _aware(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise ValueError("credential must expire after issue time")
        claims = {
            "iss": self.issuer,
            "credential_id": credential_id,
            "party": party,
            "issued_to": issued_to,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        token = _hmac(self._secret, canonical_json(claims))
        credential = OfflineCredential(credential_id, party, issued_to, issued_at, expires_at, token)
        if credential_id in self._registry and self._registry[credential_id] != credential:
            raise ValueError("credential id already issued with different claims")
        self._registry[credential_id] = credential
        return credential

    def credential(self, credential_id: str) -> OfflineCredential | None:
        return self._registry.get(credential_id)

    def sign(self, credential: OfflineCredential, message_digest: str, at: datetime) -> OfflineSignature:
        at = _aware(at, "signature time")
        if not message_digest:
            raise ValueError("message digest required")
        self.verify(credential, message_digest, at, expect_party=credential.party)
        signing_key = _hmac(credential.token.encode("ascii"), credential.credential_id).encode("ascii")
        message = canonical_json({
            "credential_id": credential.credential_id,
            "party": credential.party,
            "at": at,
            "message_digest": message_digest,
        })
        return OfflineSignature(
            credential.credential_id,
            credential.party,
            at,
            message_digest,
            _hmac(signing_key, message),
        )

    def verify(
        self,
        credential: OfflineCredential,
        message_digest: str,
        signature_time: datetime,
        expect_party: str | None = None,
        signature: OfflineSignature | None = None,
    ) -> bool:
        signature_time = _aware(signature_time, "signature time")
        expected_claims = {
            "iss": self.issuer,
            "credential_id": credential.credential_id,
            "party": credential.party,
            "issued_to": credential.issued_to,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
        }
        expected_token = _hmac(self._secret, canonical_json(expected_claims))
        if not hmac.compare_digest(expected_token, credential.token):
            raise ValueError("invalid offline credential")
        stored = self._registry.get(credential.credential_id)
        if stored is not None and stored != credential:
            raise ValueError("credential claims do not match issued credential")
        if signature_time < credential.issued_at or signature_time > credential.expires_at:
            raise ValueError("offline credential not valid at signature time")
        if expect_party is not None and credential.party != expect_party:
            raise ValueError("credential party does not match signature side")
        if signature is not None:
            if signature.credential_id != credential.credential_id:
                raise ValueError("signature credential mismatch")
            if signature.party != credential.party:
                raise ValueError("signature party mismatch")
            if signature.message_digest != message_digest:
                raise ValueError("signature message mismatch")
            signing_key = _hmac(credential.token.encode("ascii"), credential.credential_id).encode("ascii")
            message = canonical_json({
                "credential_id": signature.credential_id,
                "party": signature.party,
                "at": signature.at,
                "message_digest": signature.message_digest,
            })
            expected_digest = _hmac(signing_key, message)
            if not hmac.compare_digest(expected_digest, signature.digest):
                raise ValueError("invalid offline signature")
            if signature.at > signature_time:
                raise ValueError("signature time is after submitted event time")
        return True
