import unittest
from datetime import datetime, timezone, timedelta
from decimal import Decimal

from coldledger.controlled.handoff_flow import (
    HandoffFlow, command_fingerprint, FlowEvent, CREATOR, WITNESS,
)
from coldledger.controlled.evidence import Manifest, canonical, fingerprint
from coldledger.storage.event_store import EventStore

T = datetime(2026, 10, 2, 8, 0, tzinfo=timezone.utc)


def at(minutes):
    return T + timedelta(minutes=minutes)


def _seeded_flow(store=None, quantity="8", correction_key="k-corr"):
    f = HandoffFlow(store or EventStore())
    f.receive_stock("VAULT-A", "BATCH-1", Decimal("20"), at(0), "clerk", "k-stock")
    f.open_handoff("H1", "alice", "bob", "OXYCODONE-10", quantity,
                   "VAULT-A", "WARD-B", at(1), "k-open")
    f.attest_credential("H1", "alice", "CRED-A",
                        datetime(2026, 9, 1, tzinfo=timezone.utc), at(2), "k-cred-a")
    f.attest_credential("H1", "bob", "CRED-B",
                        datetime(2026, 9, 1, tzinfo=timezone.utc), at(3), "k-cred-b")
    f.sign("H1", "alice", CREATOR, "SIG-A", at(4), "k-sign-a")
    f.sign("H1", "bob", WITNESS, "SIG-B", at(5), "k-sign-b")
    sealed = f.seal("H1", "alice", at(6), "shift handoff", "k-seal")
    return f, sealed


class ControlledHandoffTests(unittest.TestCase):
    def test_happy_path_books_transfer_and_seals(self):
        f, sealed = _seeded_flow()
        self.assertEqual(f.balance("VAULT-A"), Decimal("12"))
        self.assertEqual(f.balance("WARD-B"), Decimal("8"))
        state = f.state("H1")
        self.assertEqual(state.status, "sealed")
        self.assertTrue(state.dual_signed())
        self.assertTrue(state.credentials_complete())
        self.assertEqual(len(state.manifests), 1)
        self.assertEqual(state.manifests[0].manifest_type, "initial")
        self.assertEqual(sealed.sealed_manifest, state.manifests[0].digest)

    def test_duplicate_submission_returns_same_result(self):
        f, sealed = _seeded_flow()
        dup_sign = f.sign("H1", "bob", WITNESS, "SIG-B", at(5), "k-sign-b")
        self.assertTrue(dup_sign.duplicate)
        self.assertEqual(dup_sign.event_digest, f._idem["k-sign-b"].event_digest)
        dup_seal = f.seal("H1", "alice", at(6), "shift handoff", "k-seal")
        self.assertTrue(dup_seal.duplicate)
        self.assertEqual(dup_seal.event_digest, sealed.event_digest)
        self.assertEqual(dup_seal.sealed_manifest, sealed.sealed_manifest)
        # A duplicate must not post a second ledger movement.
        self.assertEqual(f.balance("VAULT-A"), Decimal("12"))
        self.assertEqual(f.balance("WARD-B"), Decimal("8"))

    def test_same_key_different_command_is_rejected(self):
        f, _ = _seeded_flow()
        with self.assertRaises(ValueError):
            f.sign("H1", "bob", WITNESS, "DIFFERENT-REF", at(7), "k-seal")

    def test_duplicate_detection_survives_full_replay(self):
        store = EventStore()
        f, sealed = _seeded_flow(store)
        replayed = HandoffFlow.replay(store)
        dup = replayed.seal("H1", "alice", at(6), "shift handoff", "k-seal")
        self.assertTrue(dup.duplicate)
        self.assertEqual(dup.event_digest, sealed.event_digest)

    def test_replay_rebuilds_identical_projections(self):
        store = EventStore()
        f, _ = _seeded_flow(store)
        f.correct("H1", "bob", at(8), "broken vial", "-1", "k-corr")
        replayed = HandoffFlow.replay(store)
        self.assertEqual(replayed.balance("VAULT-A"), f.balance("VAULT-A"))
        self.assertEqual(replayed.balance("WARD-B"), f.balance("WARD-B"))
        self.assertEqual(
            [m.digest for m in replayed.manifests("H1")],
            [m.digest for m in f.manifests("H1")])
        self.assertEqual(
            [r.digest for r in replayed.audit_trail().records],
            [r.digest for r in f.audit_trail().records])
        self.assertTrue(f.audit_trail().verify())

    def test_verify_succeeds_and_detects_tampering(self):
        store = EventStore()
        f, _ = _seeded_flow(store)
        summary = f.verify("H1")
        self.assertEqual(summary["handoff"], "H1")
        self.assertEqual(summary["manifests"], 1)
        # Tamper with an already-recorded event payload.
        stored = store.read("handoff:H1")[0]
        stored.payload["drug_code"] = "TAMPERED"
        with self.assertRaises(ValueError):
            HandoffFlow.replay(store)

    def test_sealing_requires_dual_signature_and_credentials(self):
        f = HandoffFlow(EventStore())
        f.receive_stock("V", "B", "5", at(0), "c", "k1")
        f.open_handoff("H2", "a", "b", "D", "1", "V", "W", at(1), "k2")
        with self.assertRaises(ValueError):
            f.seal("H2", "a", at(2), "x", "k3")

    def test_sealing_requires_inventory(self):
        f = HandoffFlow(EventStore())
        f.receive_stock("V", "B", "2", at(0), "c", "k1")
        f.open_handoff("H2", "a", "b", "D", "5", "V", "W", at(1), "k2")
        f.attest_credential("H2", "a", "CA",
                            datetime(2026, 9, 1, tzinfo=timezone.utc), at(2), "k3")
        f.attest_credential("H2", "b", "CB",
                            datetime(2026, 9, 1, tzinfo=timezone.utc), at(3), "k4")
        f.sign("H2", "a", CREATOR, "SA", at(4), "k5")
        f.sign("H2", "b", WITNESS, "SB", at(5), "k6")
        with self.assertRaises(ValueError):
            f.seal("H2", "a", at(6), "h", "k7")

    def test_correction_appends_manifest_and_never_rewrites_initial(self):
        f, sealed = _seeded_flow()
        correction = f.correct("H1", "bob", at(8), "broken vial", "-1", "k-corr")
        manifests = f.manifests("H1")
        self.assertEqual(len(manifests), 2)
        self.assertEqual(manifests[0].digest, sealed.sealed_manifest)
        self.assertEqual(manifests[1].manifest_type, "correction")
        self.assertEqual(manifests[1].previous_manifest, manifests[0].digest)
        self.assertEqual(correction.sealed_manifest, manifests[1].digest)
        # Initial evidence still shows the original balances.
        self.assertEqual(dict(manifests[0].balances),
                         {"VAULT-A": "12", "WARD-B": "8"})
        self.assertEqual(dict(manifests[1].balances),
                         {"VAULT-A": "12", "WARD-B": "7"})
        self.assertEqual(f.balance("WARD-B"), Decimal("7"))
        f.verify_all()

    def test_positive_correction_books_from_source_to_destination(self):
        f, _ = _seeded_flow()
        f.correct("H1", "bob", at(8), "found extra vial", "2", "k-corr")
        self.assertEqual(f.balance("VAULT-A"), Decimal("10"))
        self.assertEqual(f.balance("WARD-B"), Decimal("10"))
        f.verify_all()

    def test_correction_requires_sealed_handoff(self):
        f = HandoffFlow(EventStore())
        f.receive_stock("V", "B", "5", at(0), "c", "k1")
        f.open_handoff("H2", "a", "b", "D", "1", "V", "W", at(1), "k2")
        with self.assertRaises(ValueError):
            f.correct("H2", "a", at(2), "early", "1", "k3")

    def test_correction_cannot_overdraw(self):
        f, _ = _seeded_flow()
        with self.assertRaises(ValueError):
            f.correct("H1", "bob", at(8), "impossible", "-99", "k-corr")

    def test_duplicate_correction_returns_same_result(self):
        f, _ = _seeded_flow()
        first = f.correct("H1", "bob", at(8), "broken vial", "-1", "k-corr")
        again = f.correct("H1", "bob", at(8), "broken vial", "-1", "k-corr")
        self.assertTrue(again.duplicate)
        self.assertEqual(again.event_digest, first.event_digest)
        self.assertEqual(f.balance("WARD-B"), Decimal("7"))

    def test_optimistic_concurrency_conflict(self):
        f, _ = _seeded_flow()
        # Two open commands targeting a fresh batch stream: only revision 0 wins.
        f.receive_stock("V", "B", "5", at(9), "c", "k9")
        with self.assertRaises(RuntimeError):
            f._submit("account:B", "stock_received", at(10), "c",
                      {"account": "V", "quantity": "1",
                       "idempotency_key": "k10"}, "k10", expected_revision=0)

    def test_event_time_cannot_move_backward(self):
        f, _ = _seeded_flow()
        with self.assertRaises(ValueError):
            f.correct("H1", "bob", at(1), "late arrival", "-1", "k-late")

    def test_duplicate_signature_role_rejected(self):
        f = HandoffFlow(EventStore())
        f.receive_stock("V", "B", "5", at(0), "c", "k1")
        f.open_handoff("H2", "a", "b", "D", "1", "V", "W", at(1), "k2")
        f.attest_credential("H2", "a", "CA",
                            datetime(2026, 9, 1, tzinfo=timezone.utc), at(2), "k3")
        f.attest_credential("H2", "b", "CB",
                            datetime(2026, 9, 1, tzinfo=timezone.utc), at(3), "k4")
        f.sign("H2", "a", CREATOR, "SA1", at(4), "k5")
        with self.assertRaises(ValueError):
            f.sign("H2", "a", CREATOR, "SA2", at(5), "k6")

    def test_credential_must_belong_to_a_party(self):
        f = HandoffFlow(EventStore())
        f.receive_stock("V", "B", "5", at(0), "c", "k1")
        f.open_handoff("H2", "a", "b", "D", "1", "V", "W", at(1), "k2")
        with self.assertRaises(ValueError):
            f.attest_credential("H2", "stranger", "CX",
                                datetime(2026, 9, 1, tzinfo=timezone.utc),
                                at(2), "k3")

    def test_canonical_fingerprint_is_stable(self):
        payload = {"b": 2, "a": [Decimal("1.5"), T]}
        self.assertEqual(fingerprint(payload), fingerprint(payload))
        self.assertIn(":", canonical(payload))  # ISO timestamp survives

    def test_manifest_chain_rejects_rewrite(self):
        f, sealed = _seeded_flow()
        f.correct("H1", "bob", at(8), "x", "-1", "k-corr")
        # Forging a correction that points at the initial manifest instead of
        # the latest one must be rejected when replayed.
        stream = "handoff:H1"
        revision = len(f.event_stream("H1"))
        head = f._head_digest(stream)
        forged_payload = {
            "reason": "forge", "quantity_delta": "-1",
            "previous_manifest": sealed.sealed_manifest,
            "previous_event_digest": head,
            "idempotency_key": "k-forge",
        }
        forged = FlowEvent(stream, revision + 1, "corrected", at(9), "bob",
                           dict(forged_payload, _manifest_digest="x"),
                           head, FlowEvent.digest(
                               stream, revision + 1, "corrected", at(9),
                               "bob", forged_payload, head))
        f._store.append(stream, revision, "corrected", forged.encode_payload())
        with self.assertRaises(ValueError):
            HandoffFlow.replay(f._store)


if __name__ == "__main__":
    unittest.main()
