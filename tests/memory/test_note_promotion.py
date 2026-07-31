import tempfile
import unittest
import json
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryConfirmationRequired, MemoryLifecycleConflict
from secminiagent.memory.classifier import MemoryEvaluation
from secminiagent.memory.models import (
    IndexStatus, MemoryAction, MemoryClassification, MemoryScope, NoteKind, PolicyDecision,
)
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class FakeIndex:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def index(self, metadata, content):
        self.calls.append((metadata.id, metadata.scope, content))
        if self.fail:
            raise RuntimeError("index unavailable")


class SecretEvaluator:
    def evaluate(self, candidate, context):
        return MemoryEvaluation(
            PolicyDecision(
                MemoryAction.SESSION_ONLY, MemoryClassification.SECRET, ("TEST_SECRET",),
                "test classification", target_scope=MemoryScope.THREAD,
            ),
            (), candidate,
        )


class NotePromotionTest(unittest.TestCase):
    def _note(self, root, index=None):
        _, store, lifecycle, _, service, context = create_long_term_service(root, index=index)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id)
        note = service.add_note(bound, "local memory design", MemoryScope.THREAD, NoteKind.DECISION)
        return store, service, bound, note

    def test_copy_on_promote_binds_confirmation_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, service, context, source = self._note(Path(tmp))
            with store.connection() as connection:
                before = connection.execute("SELECT scope,ciphertext,nonce FROM memories WHERE id=?", (source.note_id,)).fetchone()
            preview = service.preview_promotion(context, source.note_id, MemoryScope.SESSION)
            with self.assertRaises(MemoryConfirmationRequired):
                service.promote_note(context, source.note_id, MemoryScope.WORKSPACE, preview.confirmation_token)
            target = service.promote_note(context, source.note_id, MemoryScope.SESSION, preview.confirmation_token)
            self.assertNotEqual(target.note_id, source.note_id)
            self.assertEqual(target.scope, MemoryScope.SESSION)
            self.assertEqual(target.source_refs, (source.note_id,))
            self.assertEqual(service.promote_note(context, source.note_id, MemoryScope.SESSION, preview.confirmation_token).note_id, target.note_id)
            with store.connection() as connection:
                after = connection.execute("SELECT scope,ciphertext,nonce FROM memories WHERE id=?", (source.note_id,)).fetchone()
                promoted = connection.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (target.note_id,)).fetchone()
                promoted_row = connection.execute("SELECT * FROM memories WHERE id=?", (target.note_id,)).fetchone()
                audit = connection.execute("SELECT action,outcome,memory_id_hash,reason_code FROM memory_audit WHERE action='note_promote'").fetchone()
            self.assertEqual(tuple(before), tuple(after))
            self.assertNotEqual((bytes(before[1]), bytes(before[2])), (bytes(promoted[0]), bytes(promoted[1])))
            payload = json.loads(store.authenticate_memory_row(promoted_row).decode())
            self.assertEqual(len(payload["confirmation_receipt_hash"]), 64)
            self.assertNotIn(preview.confirmation_token, str(payload))
            self.assertEqual((audit[0], audit[1], audit[3]), ("note_promote", "success", "NOTE_PROMOTION_CONFIRMED"))
            self.assertNotEqual(audit[2], target.note_id)

    def test_workspace_only_indexes_after_confirmed_promotion_and_compensates_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = FakeIndex(fail=True)
            store, service, context, source = self._note(Path(tmp), index=index)
            session_preview = service.preview_promotion(context, source.note_id, MemoryScope.SESSION)
            session_note = service.promote_note(context, source.note_id, MemoryScope.SESSION, session_preview.confirmation_token)
            self.assertEqual(index.calls, [])
            workspace_preview = service.preview_promotion(context, session_note.note_id, MemoryScope.WORKSPACE)
            workspace_note = service.promote_note(context, session_note.note_id, MemoryScope.WORKSPACE, workspace_preview.confirmation_token)
            self.assertEqual(len(index.calls), 1)
            with store.connection() as connection:
                status = connection.execute("SELECT index_status FROM memories WHERE id=?", (workspace_note.note_id,)).fetchone()[0]
            self.assertEqual(status, IndexStatus.INDEX_FAILED.value)
            index.fail = False
            service.retry_index(context, workspace_note.note_id)
            with store.connection() as connection:
                status = connection.execute("SELECT index_status FROM memories WHERE id=?", (workspace_note.note_id,)).fetchone()[0]
            self.assertEqual(status, IndexStatus.INDEXED.value)
            self.assertEqual(len(index.calls), 2)

    def test_secret_workspace_note_is_never_sent_to_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = FakeIndex()
            _, service, context, _ = self._note(Path(tmp), index=index)
            service.notes.evaluator = SecretEvaluator()
            secret = service.add_note(context, "classified source", MemoryScope.THREAD, NoteKind.FACT)
            self.assertEqual(secret.classification, MemoryClassification.SECRET)
            preview = service.preview_promotion(context, secret.note_id, MemoryScope.WORKSPACE)
            promoted = service.promote_note(context, secret.note_id, MemoryScope.WORKSPACE, preview.confirmation_token)
            self.assertEqual(promoted.classification, MemoryClassification.SECRET)
            self.assertEqual(index.calls, [])

    def test_independent_retention_token_cannot_authorize_normal_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, service, context, source = self._note(Path(tmp))
            preview = service.preview_independent_retention(context, source.note_id)
            with self.assertRaises(MemoryConfirmationRequired):
                service.promote_note(context, source.note_id, MemoryScope.WORKSPACE, preview.confirmation_token)
            kept = service.promote_note(
                context, source.note_id, MemoryScope.WORKSPACE, preview.confirmation_token,
                purpose="independent_retention",
            )
            self.assertEqual(kept.scope, MemoryScope.WORKSPACE)


if __name__ == "__main__":
    unittest.main()
