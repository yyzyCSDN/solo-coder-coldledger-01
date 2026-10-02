from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

from coldledger.audit.trail import AuditTrail
from coldledger.custody.controlled_handoff import ControlledHandoffWorkflow, Terms
from coldledger.custody.offline_credentials import OfflineCredentialAuthority
from coldledger.inventory.ledger import InventoryLedger

UTC = timezone.utc
AT = datetime(2026, 10, 1, 9, tzinfo=UTC)


def terms(handoff_id="H-1", quantity="10"):
    return Terms(
        handoff_id=handoff_id,
        sku="CD-MOR-10",
        product_name="Morphine 10mg",
        quantity=Decimal(quantity),
        unit="ampoule",
        source_account="safe-1",
        target_account="ward-2",
        from_party="nurse-a",
        to_party="nurse-b",
        seal="SEAL-001",
        at=AT,
    )


class ControlledHandoffTests(unittest.TestCase):
    def setUp(self):
        self.authority = OfflineCredentialAuthority("test-secret")
        self.sender = self.authority.issue(
            "cred-a", "nurse-a", "Alice Nurse", AT - timedelta(days=1), AT + timedelta(days=1)
        )
        self.receiver = self.authority.issue(
            "cred-b", "nurse-b", "Bob Nurse", AT - timedelta(days=1), AT + timedelta(days=1)
        )
        self.inventory = InventoryLedger()
        self.inventory.post("safe-1", "opening", Decimal("20"), "opening stock")
        self.workflow = ControlledHandoffWorkflow(self.inventory, AuditTrail(), self.authority)

    def sign(self, workflow=None, t=None):
        workflow = workflow or self.workflow
        t = t or AT
        digest = workflow.terms_digest(terms())
        return (
            self.sender,
            self.authority.sign(self.sender, digest, t),
            self.receiver,
            self.authority.sign(self.receiver, digest, t),
        )

    def complete(self, command_prefix="cmd"):
        begin = self.workflow.begin_handoff(terms(), f"{command_prefix}-begin")
        sender, sender_sig, receiver, receiver_sig = self.sign()
        self.workflow.sign_terms("H-1", sender, sender_sig, f"{command_prefix}-sign-a")
        self.workflow.sign_terms("H-1", receiver, receiver_sig, f"{command_prefix}-sign-b")
        sealed = self.workflow.seal_handoff("H-1", f"{command_prefix}-seal", AT, "nurse-a")
        return begin, sealed

    def test_dual_signature_seal_is_idempotent_and_posts_inventory(self):
        begin, first = self.complete()
        duplicate = self.workflow.seal_handoff("H-1", "cmd-seal", AT, "nurse-a")

        self.assertEqual(begin.status, "pending")
        self.assertEqual(first.status, "sealed")
        self.assertIs(duplicate.event, first.event)
        self.assertEqual(first.event.digest, first.evidence.digest)
        self.assertEqual(2, len(first.evidence.attestations))
        self.assertEqual(self.inventory.balance("safe-1"), Decimal("10"))
        self.assertEqual(self.inventory.balance("ward-2"), Decimal("10"))
        self.assertEqual(len(self.workflow.events()), 4)

    def test_stored_event_payload_is_immutable(self):
        self.complete()
        with self.assertRaises(TypeError):
            self.workflow.events()[0].payload["actor"] = "forged"

    def test_same_command_id_with_different_payload_is_rejected(self):
        self.complete()
        with self.assertRaises(RuntimeError):
            self.workflow.seal_handoff("H-1", "cmd-seal", AT + timedelta(minutes=1), "nurse-a")

    def test_correction_appends_reversal_and_preserves_sealed_digest(self):
        _, sealed = self.complete()
        reverse_at = AT + timedelta(minutes=5)
        digest = self.workflow.reversal_digest("H-1", sealed.evidence.digest, "wrong quantity", reverse_at)
        from_sig = self.authority.sign(self.sender, digest, reverse_at)
        to_sig = self.authority.sign(self.receiver, digest, reverse_at)

        receipt = self.workflow.reverse_handoff(
            "H-1", "cmd-reverse", "wrong quantity", reverse_at, "nurse-a",
            self.sender, from_sig, self.receiver, to_sig,
        )

        self.assertEqual(receipt.status, "reversed")
        self.assertEqual(self.workflow.evidence("H-1").digest, sealed.evidence.digest)
        self.assertEqual(self.workflow.get("H-1").sealed_evidence_digest, sealed.evidence.digest)
        self.assertEqual(receipt.event.payload["original_digest"], sealed.evidence.digest)
        self.assertEqual(self.inventory.balance("safe-1"), Decimal("20"))
        self.assertEqual(self.inventory.balance("ward-2"), Decimal("0"))
        self.workflow.verify()

    def test_addendum_is_append_only_and_bound_to_original(self):
        _, sealed = self.complete()
        addendum_at = AT + timedelta(minutes=10)
        digest = self.workflow.addendum_digest(
            "H-1", sealed.evidence.digest, "A-1", "seal storage location clarified", addendum_at
        )
        receipt = self.workflow.append_addendum(
            "H-1", "cmd-addendum", "A-1", "seal storage location clarified", addendum_at, "nurse-a",
            self.sender, self.authority.sign(self.sender, digest, addendum_at),
            self.receiver, self.authority.sign(self.receiver, digest, addendum_at),
        )

        self.assertEqual(receipt.status, "sealed")
        self.assertEqual(receipt.event.payload["original_digest"], sealed.evidence.digest)
        self.assertEqual(
            self.workflow.get("H-1").addenda["A-1"]["digest"],
            receipt.event.payload["addendum_digest"],
        )
        original_events = list(self.workflow.events("H-1"))
        self.assertEqual(original_events[3].digest, sealed.evidence.digest)

    def test_replay_rebuilds_state_inventory_and_audit(self):
        _, sealed = self.complete()
        records = self.workflow.events()
        rebuilt = ControlledHandoffWorkflow.replay(
            records,
            inventory=InventoryLedger(),
            audit=AuditTrail(),
            authority=self.authority,
            opening_balances={"safe-1": Decimal("20")},
        )

        self.assertEqual(rebuilt.get("H-1").status, "sealed")
        self.assertEqual(rebuilt.evidence("H-1").digest, sealed.evidence.digest)
        self.assertEqual(rebuilt.inventory.balance("safe-1"), Decimal("10"))
        self.assertEqual(rebuilt.inventory.balance("ward-2"), Decimal("10"))
        self.assertEqual(
            rebuilt.command("cmd-seal").event.digest,
            self.workflow.command("cmd-seal").event.digest,
        )

    def test_tampered_event_fails_verification(self):
        self.complete()
        records = list(self.workflow.events())
        bad_payload = dict(records[-1].payload)
        bad_payload["actor"] = "forged"
        tampered = type(records[-1])(
            records[-1].sequence,
            records[-1].stream,
            records[-1].revision,
            records[-1].kind,
            records[-1].at,
            bad_payload,
            records[-1].previous,
            records[-1].digest,
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            ControlledHandoffWorkflow.replay(
                list(records[:-1]) + [tampered],
                inventory=InventoryLedger(),
                opening_balances={"safe-1": Decimal("20")},
            )

    def test_seal_requires_two_distinct_valid_signatures(self):
        self.workflow.begin_handoff(terms(), "begin")
        _, sender_sig, _, _ = self.sign()
        self.workflow.sign_terms("H-1", self.sender, sender_sig, "sign-a")
        with self.assertRaisesRegex(ValueError, "both parties"):
            self.workflow.seal_handoff("H-1", "seal", AT, "nurse-a")

    def test_pending_handoff_can_cancel_without_inventory_movement(self):
        self.workflow.begin_handoff(terms(), "begin")
        receipt = self.workflow.cancel_handoff("H-1", "cancel", "entry error", AT, "nurse-a")
        self.assertEqual(receipt.status, "cancelled")
        self.assertEqual(self.inventory.balance("safe-1"), Decimal("20"))
        self.assertEqual(self.inventory.balance("ward-2"), Decimal("0"))


if __name__ == "__main__":
    unittest.main()
