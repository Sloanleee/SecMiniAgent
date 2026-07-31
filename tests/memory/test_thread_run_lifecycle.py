import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryAccessDenied, MemoryLifecycleConflict, MemoryNotFound, MemoryStateIntegrityError, MemoryValidationError
from secminiagent.memory.models import MemoryAccessContext, RunStatus, ThreadStatus
from secminiagent.memory.migration_v1_v2 import legacy_main_thread_id
from tests.memory.m7_lifecycle_helpers import create_lifecycle_service


class ThreadRunLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path, self.store, self.service, self.context = create_lifecycle_service(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_main_thread_is_deterministic_and_idempotent(self):
        first = self.service.ensure_main_thread(self.context)
        second = self.service.ensure_main_thread(self.context)
        self.assertEqual(first.thread_id, second.thread_id)
        self.assertEqual(len(self.service.list_threads(self.context)), 1)
        expected = legacy_main_thread_id(self.service._id_key, self.context.session_id)
        self.assertEqual(first.thread_id, expected)

    def test_thread_create_list_activate_and_archive(self):
        thread = self.service.create_thread(self.context, "private title", "private goal")
        self.assertEqual(self.service.activate_thread(self.context, thread.thread_id).status, ThreadStatus.ACTIVE)
        archived = self.service.archive_thread(self.context, thread.thread_id)
        self.assertEqual(archived.status, ThreadStatus.ARCHIVED)
        self.assertEqual(self.service.list_threads(self.context), ())
        self.assertEqual(len(self.service.list_threads(self.context, include_archived=True)), 1)
        with self.assertRaisesRegex(MemoryLifecycleConflict, "THREAD_NOT_ACTIVE"):
            self.service.activate_thread(self.context, thread.thread_id)

    def test_run_state_machine_and_terminal_idempotence(self):
        thread = self.service.create_thread(self.context)
        context = replace(self.context, thread_id=thread.thread_id)
        run = self.service.begin_run(context, thread.thread_id)
        done = self.service.complete_run(context, run.run_id)
        self.assertEqual(done.status, RunStatus.COMPLETED)
        self.assertIsNotNone(done.completed_at)
        self.assertEqual(self.service.complete_run(context, run.run_id), done)
        with self.assertRaisesRegex(MemoryLifecycleConflict, "RUN_ALREADY_TERMINAL"):
            self.service.fail_run(context, run.run_id, "LATE_FAILURE")

    def test_reason_codes_are_bounded_and_idempotence_binds_the_reason(self):
        thread = self.service.create_thread(self.context)
        context = replace(self.context, thread_id=thread.thread_id)
        run = self.service.begin_run(context, thread.thread_id)
        with self.assertRaises(MemoryValidationError):
            self.service.fail_run(context, run.run_id, "private failure details")
        failed = self.service.fail_run(context, run.run_id, "PROVIDER_FAILED")
        self.assertEqual(self.service.fail_run(context, run.run_id, "PROVIDER_FAILED"), failed)
        with self.assertRaisesRegex(MemoryLifecycleConflict, "RUN_IDEMPOTENCY_CONFLICT"):
            self.service.fail_run(context, run.run_id, "OTHER_FAILURE")

    def test_archive_rejects_running_run_and_archived_rejects_new_run(self):
        thread = self.service.create_thread(self.context)
        context = replace(self.context, thread_id=thread.thread_id)
        run = self.service.begin_run(context, thread.thread_id)
        with self.assertRaisesRegex(MemoryLifecycleConflict, "THREAD_HAS_RUNNING_RUN"):
            self.service.archive_thread(context, thread.thread_id)
        self.service.interrupt_run(context, run.run_id)
        self.service.archive_thread(context, thread.thread_id)
        with self.assertRaisesRegex(MemoryLifecycleConflict, "THREAD_NOT_ACTIVE"):
            self.service.begin_run(context, thread.thread_id)

    def test_recovery_marks_unknown_runs_interrupted_and_is_idempotent(self):
        thread = self.service.create_thread(self.context)
        context = replace(self.context, thread_id=thread.thread_id)
        run = self.service.begin_run(context, thread.thread_id)
        recovered = self.service.recover_running_runs(context)
        self.assertEqual(recovered[0].run_id, run.run_id)
        self.assertEqual(recovered[0].status, RunStatus.INTERRUPTED)
        self.assertEqual(recovered[0].interruption_reason_code, "PROCESS_RECOVERY")
        self.assertEqual(self.service.recover_running_runs(context), ())

    def test_access_context_and_ancestry_are_enforced(self):
        thread = self.service.create_thread(self.context)
        wrong_session = MemoryAccessContext(self.context.workspace_id, "other-session", "test")
        wrong_workspace = MemoryAccessContext("b" * 64, self.context.session_id, "test")
        with self.assertRaises(MemoryNotFound):
            self.service.get_thread(wrong_session, thread.thread_id)
        with self.assertRaises(MemoryNotFound):
            self.service.get_thread(wrong_workspace, thread.thread_id)
        bound = replace(self.context, thread_id="another-thread")
        with self.assertRaises(MemoryAccessDenied):
            self.service.get_thread(bound, thread.thread_id)

    def test_parent_and_child_state_tampering_fail_closed(self):
        thread = self.service.create_thread(self.context)
        context = replace(self.context, thread_id=thread.thread_id)
        run = self.service.begin_run(context, thread.thread_id)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE threads SET next_run_no=99 WHERE thread_id=?", (thread.thread_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(MemoryStateIntegrityError):
            self.service.get_thread(self.context, thread.thread_id)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE threads SET next_run_no=? WHERE thread_id=?", (thread.next_run_no + 1, thread.thread_id))
            connection.execute("UPDATE runs SET completed_at='2026-01-01T00:00:00Z' WHERE run_id=?", (run.run_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(MemoryStateIntegrityError):
            self.service.list_runs(context, thread.thread_id)


if __name__ == "__main__":
    unittest.main()
