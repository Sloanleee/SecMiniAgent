import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryIntegrityError, MemoryLifecycleConflict, MemoryValidationError
from secminiagent.memory.models import NoteKind, NoteStatus, StructuredNote
from tests.memory.m7_lifecycle_helpers import create_note_summary_services


class StructuredNotesTest(unittest.TestCase):
    def test_model_note_requires_source_and_persists_candidate_with_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, notes, _, context = create_note_summary_services(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "source statement"})
            note = notes.add_candidate(
                bound, kind=NoteKind.FACT, content="model-proposed fact",
                source_refs=(source.message_id,), created_by="model", confidence=0.7,
            )
            self.assertEqual(note.status, NoteStatus.CANDIDATE)
            self.assertEqual(notes.get(bound, note.note_id), note)
            self.assertNotIn(b"model-proposed fact", path.read_bytes())
            connection = sqlite3.connect(path)
            try:
                relation = connection.execute("SELECT relation_type,target_memory_id FROM memory_relations WHERE source_memory_id=?", (note.note_id,)).fetchone()
            finally:
                connection.close()
            self.assertEqual(relation, ("derived_from", source.message_id))

    def test_derived_note_without_source_is_rejected_by_value_object(self):
        with self.assertRaises(MemoryValidationError):
            StructuredNote(
                "n", "w", "s", "t", NoteKind.FACT, "content", created_by="model",
            )

    def test_revision_creates_new_record_and_supersedes_active_old_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, lifecycle, transcript, notes, _, context = create_note_summary_services(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "source"})
            old = notes.add_candidate(bound, kind=NoteKind.DECISION, content="old", source_refs=(source.message_id,))
            with store.connection(immediate=True) as connection:
                row = connection.execute("SELECT * FROM memories WHERE id=?", (old.note_id,)).fetchone()
                notes._set_status(connection, row, NoteStatus.ACTIVE)
            revised = notes.add_candidate(
                bound, kind=NoteKind.DECISION, content="new", source_refs=(source.message_id,),
                supersedes_id=old.note_id,
            )
            self.assertNotEqual(old.note_id, revised.note_id)
            self.assertEqual(revised.revision, 2)
            self.assertEqual(notes.get(bound, old.note_id).status, NoteStatus.SUPERSEDED)
            self.assertEqual(notes.get(bound, revised.note_id).status, NoteStatus.CANDIDATE)

    def test_relation_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, lifecycle, transcript, notes, _, context = create_note_summary_services(Path(tmp))
            thread = lifecycle.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = lifecycle.begin_run(bound, thread.thread_id)
            source = transcript.append(bound, run.run_id, {"role": "user", "content": "source"})
            note = notes.add_candidate(bound, kind=NoteKind.FINDING, content="finding", source_refs=(source.message_id,))
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE memory_relations SET relation_type='supports' WHERE source_memory_id=?", (note.note_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(MemoryIntegrityError):
                notes.get(bound, note.note_id)


if __name__ == "__main__":
    unittest.main()
