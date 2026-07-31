import tempfile
import unittest
import sqlite3
from dataclasses import replace
from pathlib import Path

from tests.memory.m7_lifecycle_helpers import create_transcript_service


class ThreadResumeTest(unittest.TestCase):
    def test_resume_does_not_mutate_memory_or_run_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, _, lifecycle, transcript, context = create_transcript_service(root)
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            item = transcript.append(bound, run.run_id, {"role": "user", "content": "read only"})
            connection = sqlite3.connect(path)
            try:
                before_memory = connection.execute("SELECT state_version,last_recalled_at FROM memories WHERE id=?", (item.message_id,)).fetchone()
                before_run = connection.execute("SELECT state_version,turn_count FROM runs WHERE run_id=?", (run.run_id,)).fetchone()
            finally:
                connection.close()
            transcript.resume(bound)
            connection = sqlite3.connect(path)
            try:
                after_memory = connection.execute("SELECT state_version,last_recalled_at FROM memories WHERE id=?", (item.message_id,)).fetchone()
                after_run = connection.execute("SELECT state_version,turn_count FROM runs WHERE run_id=?", (run.run_id,)).fetchone()
            finally:
                connection.close()
            self.assertEqual(before_memory, after_memory)
            self.assertEqual(before_run, after_run)

    def test_close_reopen_append_and_resume_preserves_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, lifecycle, transcript, context = create_transcript_service(root)
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            first_run = lifecycle.begin_run(bound, thread.thread_id)
            transcript.append(bound, first_run.run_id, {"role": "user", "content": "first"})
            lifecycle.complete_run(bound, first_run.run_id)

            # Recreate service objects over the same persistent database.
            from secminiagent.memory.state_auth import StateAuthenticator
            from secminiagent.memory.store_v2 import SQLiteV2Store
            from secminiagent.memory.thread_run_service import ThreadRunService
            from secminiagent.memory.thread_run_store import ThreadRunStore
            from secminiagent.memory.transcript_v2 import ThreadTranscriptService
            keys = transcript.store.key_provider
            state = StateAuthenticator(keys.derive_key(context.workspace_id, "state")[0], relation_key=keys.derive_key(context.workspace_id, "relation")[0])
            store = SQLiteV2Store(root / "memory-v2.db", key_provider=keys, authenticator=state, shadow=False)
            lifecycle_store = ThreadRunStore(store)
            reopened_lifecycle = ThreadRunService(lifecycle_store, id_key=keys.derive_key(context.workspace_id, "migration")[0])
            reopened = ThreadTranscriptService(store, reopened_lifecycle, lifecycle_store, envelope_key=keys.derive_key(context.workspace_id, "provenance")[0])
            second_run = reopened_lifecycle.begin_run(bound, thread.thread_id)
            reopened.append(bound, second_run.run_id, {"role": "user", "content": "second"})
            self.assertEqual([item.message["content"] for item in reopened.resume(bound)], ["first", "second"])


if __name__ == "__main__":
    unittest.main()
