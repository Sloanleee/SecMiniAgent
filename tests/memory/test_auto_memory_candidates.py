import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.candidate_extractor import ControlledCandidateService
from secminiagent.memory.errors import MemoryPolicyDenied
from secminiagent.memory.models import CandidateProposal, NoteKind, NoteStatus, VerificationStatus
from tests.memory.m7_lifecycle_helpers import create_long_term_service


class AutoMemoryCandidatesTest(unittest.TestCase):
    def test_completed_persisted_source_only_creates_model_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, transcript, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "source observation"})
            candidates = ControlledCandidateService(service, dedup_key=store.key_provider.derive_key(context.workspace_id, "dedup")[0])
            proposal = CandidateProposal(NoteKind.FACT, "derived observation", (source.message_id,), 0.8)
            with self.assertRaises(MemoryPolicyDenied):
                candidates.submit(bound, proposal)
            lifecycle.complete_run(bound, run.run_id)
            candidate = candidates.submit(bound, proposal)
            self.assertEqual((candidate.status, candidate.verification), (NoteStatus.CANDIDATE, VerificationStatus.MODEL_INFERRED))
            confirmed = service.confirm_note(bound, candidate.note_id, candidate.revision)
            self.assertEqual((confirmed.status, confirmed.verification), (NoteStatus.ACTIVE, VerificationStatus.USER_CONFIRMED))


if __name__ == "__main__":
    unittest.main()
