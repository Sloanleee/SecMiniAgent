import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryIntegrityError, MemoryLifecycleConflict
from secminiagent.memory.models import NoteStatus
from secminiagent.memory.models import MemoryClassification
from tests.memory.m7_lifecycle_helpers import create_note_summary_services
from secminiagent.memory.summarizer import SummaryTriggerPolicy


class FixedGenerator:
    def summarize(self, previous, messages):
        return {
            "goal": "safe goal", "verified_facts": [], "decisions": [],
            "completed_actions": [str(messages[-1].message.get("content"))],
            "pending_actions": [], "findings": [], "entities": [], "open_questions": [],
        }


class RollingSummaryTest(unittest.TestCase):
    def test_summary_watermark_advances_and_old_version_is_superseded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            first_run = lifecycle.begin_run(bound, thread.thread_id)
            first_message = transcript.append(bound, first_run.run_id, {"role": "user", "content": "first"})
            lifecycle.complete_run(bound, first_run.run_id)
            first = summaries.build(bound)
            self.assertEqual(first.covered_through_sequence, first_message.thread_sequence)
            second_run = lifecycle.begin_run(bound, thread.thread_id)
            second_message = transcript.append(bound, second_run.run_id, {"role": "assistant", "content": "second"})
            lifecycle.complete_run(bound, second_run.run_id)
            second = summaries.build(bound)
            self.assertEqual(second.version, 2)
            self.assertGreater(second.covered_through_sequence, first.covered_through_sequence)
            self.assertEqual(second.covered_through_sequence, second_message.thread_sequence)
            self.assertEqual(summaries.active(bound).summary_id, second.summary_id)

    def test_incomplete_tool_group_does_not_advance_watermark(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "assistant", "content": None, "tool_calls": [{"id": "pending", "type": "function", "function": {"name": "x", "arguments": "{}"}}]})
            with self.assertRaisesRegex(MemoryLifecycleConflict, "SUMMARY_NO_NEW_COMPLETE_MESSAGES"):
                summaries.build(bound)

    def test_summary_provenance_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "source"})
            lifecycle.complete_run(bound, run.run_id)
            summary = summaries.build(bound)
            connection = sqlite3.connect(path)
            try:
                connection.execute("DELETE FROM memory_relations WHERE source_memory_id=?", (summary.summary_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(MemoryIntegrityError):
                summaries.active(bound)

    def test_summary_inherits_highest_source_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "internal OT address 10.20.30.40"})
            self.assertEqual(source.classification, MemoryClassification.CONFIDENTIAL)
            lifecycle.complete_run(bound, run.run_id)
            self.assertEqual(summaries.build(bound).classification, MemoryClassification.CONFIDENTIAL)

    def test_configurable_trigger_has_bounded_thresholds(self):
        with self.assertRaises(ValueError):
            SummaryTriggerPolicy(max_unsummarized_messages=0)
        policy = SummaryTriggerPolicy(max_unsummarized_messages=1, max_unsummarized_chars=1000)
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            summaries.trigger_policy = policy
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "trigger"})
            self.assertTrue(summaries.should_build(bound))
            self.assertIsNotNone(summaries.maybe_build(bound))

    def test_source_classification_tampering_cannot_lower_summary_inheritance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, _, summaries, context = create_note_summary_services(Path(tmp), generator=FixedGenerator())
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "classified source"})
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE memories SET classification='public' WHERE id=?", (source.message_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(MemoryIntegrityError):
                summaries.build(bound)


if __name__ == "__main__":
    unittest.main()
