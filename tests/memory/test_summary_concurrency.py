import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryMigrationConflict, MemoryPolicyDenied
from tests.memory.m7_lifecycle_helpers import create_note_summary_services


class CallbackGenerator:
    def __init__(self, callback=None, verified=False):
        self.callback = callback
        self.verified = verified

    def summarize(self, previous, messages):
        if self.callback:
            callback, self.callback = self.callback, None
            callback()
        return {
            "goal": "", "verified_facts": ["invented fact"] if self.verified else [],
            "decisions": [], "completed_actions": [], "pending_actions": [],
            "findings": [], "entities": [], "open_questions": [],
        }


class SummaryConcurrencyTest(unittest.TestCase):
    def test_message_arriving_during_generation_causes_cas_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, store, lifecycle, transcript, _, summaries, context = create_note_summary_services(root)
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "first"})
            summaries.generator = CallbackGenerator(
                lambda: transcript.append(bound, run.run_id, {"role": "assistant", "content": "arrived during summary"})
            )
            with self.assertRaisesRegex(MemoryMigrationConflict, "SUMMARY_SOURCE_CHANGED"):
                summaries.build(bound)
            with store.connection() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories WHERE memory_type='thread_summary'").fetchone()[0], 0)
            self.assertEqual(len(transcript.resume(bound)), 2)

    def test_model_cannot_put_unknown_source_claim_into_verified_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=CallbackGenerator(verified=True))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "unverified statement"})
            with self.assertRaisesRegex(MemoryPolicyDenied, "SUMMARY_UNVERIFIED_FACT_CLAIM"):
                summaries.build(bound)


if __name__ == "__main__":
    unittest.main()
