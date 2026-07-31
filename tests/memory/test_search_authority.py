import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.models import MemoryScope, NoteKind
from secminiagent.memory.search import HybridMemorySearch
from secminiagent.memory.canonical import canonical_timestamp
from secminiagent.memory.store_v2 import memory_state_fields
from tests.memory.m7_lifecycle_helpers import create_long_term_service
from tests.memory.test_hybrid_search import FakeCandidates


class SearchAuthorityTest(unittest.TestCase):
    def test_chroma_ids_cannot_bypass_thread_scope_or_retracted_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            first = lifecycle.create_thread(context)
            second = lifecycle.create_thread(context)
            allowed_context = replace(context, thread_id=first.thread_id)
            foreign_context = replace(context, thread_id=second.thread_id)
            allowed = service.add_note(allowed_context, "authorized turbine finding", MemoryScope.THREAD, NoteKind.FINDING)
            foreign = service.add_note(foreign_context, "foreign turbine finding", MemoryScope.THREAD, NoteKind.FINDING)
            service.retract_note(allowed_context, allowed.note_id, "USER_REQUEST", allowed.revision)
            index = FakeCandidates((foreign.note_id, allowed.note_id, "missing-id"))
            search = HybridMemorySearch(
                service.store, service.lifecycle_store,
                index=index,
            )
            self.assertEqual(search.search(allowed_context, "turbine finding"), ())
            self.assertEqual(set(search.reconcile_stale(allowed_context, dry_run=True)), {foreign.note_id, allowed.note_id, "missing-id"})
            search.reconcile_stale(allowed_context)
            self.assertEqual(set(index.deleted), {foreign.note_id, allowed.note_id, "missing-id"})

    def test_state_tampering_fails_closed_after_sql_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            note = service.add_note(bound, "tamper target phrase", MemoryScope.THREAD, NoteKind.FACT)
            import sqlite3
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE memories SET state_version=state_version+1 WHERE id=?", (note.note_id,))
                connection.commit()
            finally:
                connection.close()
            search = HybridMemorySearch(service.store, service.lifecycle_store)
            self.assertEqual(search.search(bound, "tamper target"), ())

    def test_expired_note_is_filtered_before_decrypt_and_search_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, _, service, context = create_long_term_service(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            note = service.add_note(bound, "expired authority phrase", MemoryScope.THREAD, NoteKind.FACT)
            with store.connection(immediate=True) as connection:
                row = connection.execute("SELECT * FROM memories WHERE id=?", (note.note_id,)).fetchone()
                current = dict(row)
                current.update(
                    expires_at=canonical_timestamp(datetime.now(timezone.utc) - timedelta(seconds=1)),
                    state_version=int(row["state_version"]) + 1,
                    updated_at=canonical_timestamp(datetime.now(timezone.utc)),
                )
                current["state_mac"] = store.authenticator.sign_memory(memory_state_fields(current))
                connection.execute("UPDATE memories SET expires_at=?,state_version=?,updated_at=?,state_mac=? WHERE id=?", (current["expires_at"], current["state_version"], current["updated_at"], current["state_mac"], note.note_id))
            with store.connection() as connection:
                before = tuple(connection.execute("SELECT state_version,last_recalled_at FROM memories WHERE id=?", (note.note_id,)).fetchone())
            self.assertEqual(HybridMemorySearch(store, service.lifecycle_store).search(bound, "expired authority"), ())
            with store.connection() as connection:
                after = tuple(connection.execute("SELECT state_version,last_recalled_at FROM memories WHERE id=?", (note.note_id,)).fetchone())
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
