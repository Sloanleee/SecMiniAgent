import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from secminiagent.memory.errors import MemoryLifecycleConflict
from secminiagent.memory.models import RunStatus
from tests.memory.m7_lifecycle_helpers import create_lifecycle_service


class ThreadRunConcurrencyTest(unittest.TestCase):
    def test_thread_and_run_sequence_allocations_are_transactional(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, service, context = create_lifecycle_service(Path(tmp))
            thread = service.create_thread(context)
            bound = replace(context, thread_id=thread.thread_id)
            run = service.begin_run(bound, thread.thread_id)
            with store.connection(immediate=True) as connection:
                self.assertEqual(store.allocate_thread_sequence(connection, context.workspace_id, context.session_id, thread.thread_id), 1)
                self.assertEqual(store.allocate_run_sequence(connection, context.workspace_id, context.session_id, thread.thread_id, run.run_id), 1)
            try:
                with store.connection(immediate=True) as connection:
                    self.assertEqual(store.allocate_thread_sequence(connection, context.workspace_id, context.session_id, thread.thread_id), 2)
                    self.assertEqual(store.allocate_run_sequence(connection, context.workspace_id, context.session_id, thread.thread_id, run.run_id), 2)
                    raise RuntimeError("ROLLBACK")
            except RuntimeError:
                pass
            with store.connection(immediate=True) as connection:
                self.assertEqual(store.allocate_thread_sequence(connection, context.workspace_id, context.session_id, thread.thread_id), 2)
                self.assertEqual(store.allocate_run_sequence(connection, context.workspace_id, context.session_id, thread.thread_id, run.run_id), 2)

    def test_two_concurrent_begin_run_calls_create_only_one_running_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, service, context = create_lifecycle_service(Path(tmp))
            thread = service.create_thread(context)
            context = replace(context, thread_id=thread.thread_id)
            barrier = threading.Barrier(2)
            results = []

            def worker():
                barrier.wait()
                try:
                    results.append(service.begin_run(context, thread.thread_id))
                except MemoryLifecycleConflict as exc:
                    results.append(str(exc))

            workers = [threading.Thread(target=worker) for _ in range(2)]
            for worker_thread in workers:
                worker_thread.start()
            for worker_thread in workers:
                worker_thread.join()
            successes = [item for item in results if not isinstance(item, str)]
            self.assertEqual(len(successes), 1, results)
            self.assertEqual(successes[0].status, RunStatus.RUNNING)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM runs WHERE status='running'").fetchone()[0], 1)
            finally:
                connection.close()

    def test_different_threads_can_run_and_run_numbers_do_not_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, service, context = create_lifecycle_service(Path(tmp))
            one = service.create_thread(context)
            two = service.create_thread(context)
            run_one = service.begin_run(replace(context, thread_id=one.thread_id), one.thread_id)
            run_two = service.begin_run(replace(context, thread_id=two.thread_id), two.thread_id)
            self.assertEqual((run_one.run_no, run_two.run_no), (1, 1))
            service.complete_run(replace(context, thread_id=one.thread_id), run_one.run_id)
            next_run = service.begin_run(replace(context, thread_id=one.thread_id), one.thread_id)
            self.assertEqual(next_run.run_no, 2)


if __name__ == "__main__":
    unittest.main()
