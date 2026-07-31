import unittest
import tempfile
from pathlib import Path

from secminiagent.memory.errors import MemoryStateIntegrityError
from secminiagent.memory.keys import WorkspaceKeyManager
from secminiagent.memory.state_auth import StateAuthenticator
from tests.memory.helpers import ReversingProtector


class StateAuthTest(unittest.TestCase):
    def setUp(self):
        self.auth = StateAuthenticator(b"s" * 32, relation_key=b"r" * 32)

    def test_state_mac_rejects_thread_counter_tampering(self):
        fields = {"workspace_id": "w", "session_id": "s", "thread_id": "t", "state_version": 1, "status": "active", "revision": 1, "next_run_no": 1, "next_thread_sequence": 2, "updated_at": "2026", "deleted_at": None}
        mac = self.auth.sign_thread(fields)
        with self.assertRaises(MemoryStateIntegrityError):
            self.auth.verify_thread(mac, {**fields, "next_run_no": 2})

    def test_state_mac_rejects_run_completion_tampering(self):
        fields = {"workspace_id": "w", "session_id": "s", "thread_id": "t", "run_id": "r", "state_version": 1, "run_no": 1, "status": "completed", "next_run_sequence": 2, "input_message_id": "u", "final_message_id": "m", "turn_count": 1, "started_at": "2026", "completed_at": "2026", "interruption_reason_code": None, "migration_origin": None, "deleted_at": None}
        mac = self.auth.sign_run(fields)
        with self.assertRaises(MemoryStateIntegrityError):
            self.auth.verify_run(mac, {**fields, "final_message_id": "other"})

    def test_state_mac_rejects_memory_deletion_and_expiry_tampering(self):
        fields = {"workspace_id": "w", "session_id": None, "thread_id": None, "run_id": None, "memory_id": "m", "state_version": 1, "lifecycle_status": "active", "deleted_at": None, "expires_at": None, "pinned": 0, "retention_policy_id": None, "index_status": "not_indexed", "last_recalled_at": None, "last_validated_at": None, "provenance_digest": b"p", "updated_at": "2026"}
        mac = self.auth.sign_memory(fields)
        with self.assertRaises(MemoryStateIntegrityError):
            self.auth.verify_memory(mac, {**fields, "deleted_at": "2026-01-01T00:00:00.000000Z"})

    def test_state_mac_rejects_migration_phase_tampering(self):
        fields = {"journal_entry_id": "e", "migration_id": "x", "state_version": 1, "from_version": 1, "to_version": 2, "phase": "prepared", "source_record_id_hash": "s", "target_record_id_hash": "t", "outcome": "ready", "created_at": "2026", "updated_at": "2026"}
        mac = self.auth.sign_migration_entry(fields)
        with self.assertRaises(MemoryStateIntegrityError):
            self.auth.verify_migration_entry(mac, {**fields, "phase": "switched"})

    def test_key_purposes_derive_distinct_stable_workspace_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = WorkspaceKeyManager(Path(tmp), ReversingProtector())
            workspace_a = "a" * 64
            workspace_b = "b" * 64
            manager.get_key(workspace_a)
            manager.get_key(workspace_b)
            purposes = ("state", "relation", "provenance", "migration", "dedup")
            derived = [manager.derive_key(workspace_a, purpose)[0] for purpose in purposes]
            self.assertEqual(len(set(derived)), len(purposes))
            self.assertEqual(derived[0], manager.derive_key(workspace_a, "state")[0])
            self.assertNotEqual(derived[0], manager.derive_key(workspace_b, "state")[0])

    def test_deletion_state_has_entity_specific_mac(self):
        job = {"job_id": "j", "workspace_id": "w", "state_version": 1, "root_type": "thread", "root_id": "t", "status": "running", "reason_code": "TEST", "updated_at": "2026"}
        item = {"job_id": "j", "target_type": "memory", "target_id": "m", "state_version": 1, "phase": "planned", "outcome": "pending", "selected_action": "retract", "target_revision": 1, "confirmation_receipt_hash": None, "independent_record_id": None, "last_error_code": None, "updated_at": "2026"}
        self.assertNotEqual(self.auth.sign_deletion_job(job), self.auth.sign_deletion_item(item))


if __name__ == "__main__":
    unittest.main()
