import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryIntegrityError, MemoryLifecycleConflict
from tests.memory.m7_lifecycle_helpers import create_transcript_service


class ThreadTranscriptTest(unittest.TestCase):
    def test_interleaved_threads_resume_only_the_target_thread(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            one = lifecycle.create_thread(context)
            two = lifecycle.create_thread(context)
            one_context = replace(context, thread_id=one.thread_id)
            two_context = replace(context, thread_id=two.thread_id)
            one_run = lifecycle.begin_run(one_context, one.thread_id)
            two_run = lifecycle.begin_run(two_context, two.thread_id)
            transcript.append(one_context, one_run.run_id, {"role": "user", "content": "thread one secret"})
            transcript.append(two_context, two_run.run_id, {"role": "user", "content": "thread two secret"})
            transcript.append(one_context, one_run.run_id, {"role": "assistant", "content": "one answer"})
            self.assertEqual([item.message["content"] for item in transcript.resume(one_context)], ["thread one secret", "one answer"])
            self.assertEqual([item.message["content"] for item in transcript.resume(two_context)], ["thread two secret"])

    def test_tool_results_must_match_one_call_in_the_same_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            with self.assertRaisesRegex(MemoryLifecycleConflict, "TOOL_RESULT_ORPHANED"):
                transcript.append(bound, run.run_id, {"role": "tool", "tool_call_id": "call-1", "content": "orphan"})
            transcript.append(bound, run.run_id, {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "read", "arguments": "{}"}}],
            })
            with self.assertRaisesRegex(MemoryLifecycleConflict, "TOOL_RESULTS_PENDING"):
                transcript.append(bound, run.run_id, {"role": "assistant", "content": "cannot skip pending result"})
            transcript.append(bound, run.run_id, {"role": "tool", "tool_call_id": "call-1", "content": "result"})
            with self.assertRaisesRegex(MemoryLifecycleConflict, "TOOL_RESULT_DUPLICATE"):
                transcript.append(bound, run.run_id, {"role": "tool", "tool_call_id": "call-1", "content": "again"})

    def test_terminal_run_rejects_append_and_sequences_are_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            first = transcript.append(bound, run.run_id, {"role": "user", "content": "one"})
            second = transcript.append(bound, run.run_id, {"role": "assistant", "content": "two"})
            self.assertEqual((first.thread_sequence, second.thread_sequence), (1, 2))
            self.assertEqual((first.run_sequence, second.run_sequence), (1, 2))
            lifecycle.complete_run(bound, run.run_id)
            with self.assertRaisesRegex(MemoryLifecycleConflict, "RUN_NOT_RUNNING"):
                transcript.append(bound, run.run_id, {"role": "user", "content": "late"})

    def test_bound_metadata_and_ciphertext_tampering_fail_closed(self):
        for mutation in ("sequence", "ciphertext"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                path, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
                thread = lifecycle.create_thread(context)
                bound = replace(context, thread_id=thread.thread_id)
                run = lifecycle.begin_run(bound, thread.thread_id)
                item = transcript.append(bound, run.run_id, {"role": "user", "content": "canary"})
                connection = sqlite3.connect(path)
                try:
                    if mutation == "sequence":
                        connection.execute("UPDATE memories SET thread_sequence=77 WHERE id=?", (item.message_id,))
                    else:
                        value = connection.execute("SELECT ciphertext FROM memories WHERE id=?", (item.message_id,)).fetchone()[0]
                        connection.execute("UPDATE memories SET ciphertext=? WHERE id=?", (bytes(value)[:-1] + b"x", item.message_id))
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(MemoryIntegrityError):
                    transcript.resume(bound)

    def test_hard_secret_is_redacted_before_v2_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            secret = 'password = "Synthet1c-M7-Secret"'
            item = transcript.append(bound, run.run_id, {"role": "user", "content": secret})
            self.assertEqual(item.message["content"], "[REDACTED:SECRET]")
            self.assertNotIn(secret.encode(), path.read_bytes())

    def test_tampered_run_parent_is_verified_before_message_decryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, context = create_transcript_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, run.run_id, {"role": "user", "content": "parent check"})
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE runs SET turn_count=99 WHERE run_id=?", (run.run_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(MemoryIntegrityError):
                transcript.resume(bound)


if __name__ == "__main__":
    unittest.main()
