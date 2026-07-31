import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.candidate_extractor import ControlledCandidateService
from secminiagent.memory.models import CandidateProposal, MemoryScope, NoteKind, NoteStatus
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class MemoryDedupConflictTest(unittest.TestCase):
    def _setup(self, root):
        _, store, lifecycle, transcript, service, context = create_long_term_service(root)
        thread = lifecycle.create_thread(context)
        bound = replace(context, thread_id=thread.thread_id)
        run = lifecycle.begin_run(bound, thread.thread_id)
        source = transcript.append(bound, run.run_id, {"role": "user", "content": "persisted source"})
        lifecycle.complete_run(bound, run.run_id)
        candidates = ControlledCandidateService(service, dedup_key=store.key_provider.derive_key(context.workspace_id, "dedup")[0])
        return store, service, candidates, bound, source

    def test_hmac_fingerprint_is_idempotent_under_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _, candidates, context, source = self._setup(Path(tmp))
            first = candidates.submit(context, CandidateProposal(NoteKind.FACT, "Same   Semantic Fact", (source.message_id,), 0.7))
            second = candidates.submit(context, CandidateProposal(NoteKind.FACT, " same semantic fact ", (source.message_id,), 0.7))
            self.assertEqual(first.note_id, second.note_id)
            with store.connection() as connection:
                supports = connection.execute("SELECT COUNT(*) FROM memory_relations WHERE source_memory_id=? AND target_memory_id=? AND relation_type='supports'", (first.note_id, source.message_id)).fetchone()[0]
            self.assertEqual(supports, 1)

    def test_conflict_does_not_overwrite_confirmed_fact_and_revision_waits_for_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, service, candidates, context, source = self._setup(Path(tmp))
            original = service.add_note(context, "controller mode is automatic", MemoryScope.THREAD, NoteKind.FACT)
            conflict = candidates.submit(context, CandidateProposal(
                NoteKind.FACT, "controller mode is manual", (source.message_id,), 0.8,
                relationship="conflict", related_note_id=original.note_id,
            ))
            self.assertEqual(service.get_note(context, original.note_id).status, NoteStatus.ACTIVE)
            self.assertEqual(conflict.status, NoteStatus.CANDIDATE)
            with store.connection() as connection:
                count = connection.execute("SELECT COUNT(*) FROM memory_relations WHERE relation_type='conflicts_with' AND (source_memory_id=? OR target_memory_id=?)", (conflict.note_id, conflict.note_id)).fetchone()[0]
            self.assertEqual(count, 2)
            revision = candidates.submit(context, CandidateProposal(
                NoteKind.FACT, "controller mode is supervised", (source.message_id,), 0.9,
                relationship="revision", related_note_id=original.note_id,
            ))
            self.assertEqual(revision.revision, original.revision + 1)
            self.assertEqual(service.get_note(context, original.note_id).status, NoteStatus.ACTIVE)
            service.confirm_note(context, revision.note_id, revision.revision)
            self.assertEqual(service.get_note(context, original.note_id).status, NoteStatus.SUPERSEDED)


if __name__ == "__main__":
    unittest.main()
