import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from secminiagent.cli import build_memory_parser, run_memory_command
from secminiagent.memory import MemoryAccessContext, MemoryCandidate, MemoryQuery, MemoryScope, MemorySource, MemoryType
from secminiagent.memory.errors import MemoryDependencyUnavailable
from secminiagent.memory.errors import MemoryNotFound
from secminiagent.memory.factory import create_local_memory

from tests.memory.helpers import build_test_service


WORKSPACE = "c" * 64
CONTEXT = MemoryAccessContext(WORKSPACE, "session-a", "local")


class FailingDeleteIndex:
    def __init__(self):
        self.fail_delete = True
        self.items = set()

    def index(self, metadata, _text):
        self.items.add(metadata.id)

    def delete(self, memory_id, _context):
        if self.fail_delete:
            raise RuntimeError("synthetic index outage")
        self.items.discard(memory_id)

    def candidate_ids(self, _query, _context):
        return tuple(self.items)

    def reset(self):
        self.items.clear()


def workspace_candidate(text="safe workspace fact"):
    return MemoryCandidate(
        MemoryType.PROJECT_FACT,
        text,
        MemoryScope.WORKSPACE,
        MemorySource("unit_test", user_confirmed=True),
    )


class DeletionAndCliTest(unittest.TestCase):
    def test_delete_revokes_access_before_index_cleanup_and_retry_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = FailingDeleteIndex()
            service, store, _ = build_test_service(root, index=index)
            metadata = service.remember(workspace_candidate(), CONTEXT)
            receipt = service.forget(metadata.id, CONTEXT)
            self.assertTrue(receipt.authoritative_access_revoked)
            self.assertTrue(receipt.cleanup_pending)
            with self.assertRaises(MemoryNotFound):
                service.recall(metadata.id, CONTEXT)
            self.assertEqual(store.status(WORKSPACE)["pending_deletions"], 1)
            self.assertEqual(service.search(MemoryQuery(text="safe"), CONTEXT), ())

            # Simulate a process restart with a fresh service and recovered index.
            recovered_index = FailingDeleteIndex()
            recovered_index.fail_delete = False
            recovered_service, recovered_store, _ = build_test_service(root, index=recovered_index)
            self.assertEqual(recovered_service.retry_pending_deletions(CONTEXT), (metadata.id,))
            self.assertEqual(recovered_store.status(WORKSPACE)["pending_deletions"], 0)

    def test_clear_session_does_not_delete_workspace_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = build_test_service(Path(tmp))
            session = service.remember(
                MemoryCandidate(
                    MemoryType.USER_NOTE,
                    "session fact",
                    MemoryScope.SESSION,
                    MemorySource("unit_test", user_confirmed=True),
                ),
                CONTEXT,
            )
            workspace = service.remember(workspace_candidate(), CONTEXT)
            receipts = service.clear_session(CONTEXT)
            self.assertEqual([item.memory_id for item in receipts], [session.id])
            self.assertEqual(service.recall(workspace.id, CONTEXT).content, "safe workspace fact")

    def test_audit_has_delete_evidence_without_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = build_test_service(Path(tmp))
            text = "delete-audit-secretless-marker"
            metadata = service.remember(workspace_candidate(text), CONTEXT)
            service.forget(metadata.id, CONTEXT)
            rendered = repr(service.audit_events(CONTEXT))
            self.assertIn("DELETE_COMPLETE", rendered)
            self.assertNotIn(text, rendered)

    def test_clear_workspace_removes_memories_from_other_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _, _ = build_test_service(Path(tmp))
            other_context = MemoryAccessContext(WORKSPACE, "session-b", "local")
            first = service.remember(
                MemoryCandidate(
                    MemoryType.USER_NOTE,
                    "first session",
                    MemoryScope.SESSION,
                    MemorySource("unit_test", user_confirmed=True),
                ),
                CONTEXT,
            )
            second = service.remember(
                MemoryCandidate(
                    MemoryType.USER_NOTE,
                    "second session",
                    MemoryScope.SESSION,
                    MemorySource("unit_test", user_confirmed=True),
                ),
                other_context,
            )
            receipts = service.clear_workspace(CONTEXT)
            self.assertEqual({item.memory_id for item in receipts}, {first.id, second.id})
            self.assertEqual(service.status(CONTEXT)["live_memories"], 0)

    def test_memory_cli_parser_exposes_required_actions(self):
        parser = build_memory_parser()
        for action in ["status", "list", "inspect", "forget", "clear", "audit", "migrate-sessions"]:
            args = [action]
            if action in {"inspect", "forget"}:
                args.append("memory-id")
            if action == "clear":
                args.append("--workspace")
            self.assertEqual(parser.parse_args(args).memory_action, action)

    def test_memory_status_cli_runs_in_local_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = io.StringIO()
            with redirect_stdout(output):
                code = run_memory_command(["--cwd", tmp, "status"])
            self.assertEqual(code, 0)
            self.assertIn("live_memories", output.getvalue())

    def test_core_memory_service_still_starts_when_optional_chroma_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "secminiagent.memory.factory.ChromaMemoryIndex",
                side_effect=MemoryDependencyUnavailable("not installed"),
            ):
                service, context = create_local_memory(Path(tmp), enable_chroma=True)
            try:
                self.assertEqual(service.status(context)["vector_index_enabled"], 0)
            finally:
                service.close()

    def test_list_inspect_audit_and_forget_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            session_id = "cli-session"
            service, context = create_local_memory(
                Path(tmp),
                provider="local",
                session_id=session_id,
                enable_chroma=False,
            )
            metadata = service.remember(
                MemoryCandidate(
                    MemoryType.USER_NOTE,
                    "CLI inspection fact",
                    MemoryScope.SESSION,
                    MemorySource("unit_test", user_confirmed=True),
                ),
                context,
            )
            service.close()

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    run_memory_command(["--cwd", tmp, "list", "--session", session_id]),
                    0,
                )
            self.assertIn(metadata.id, output.getvalue())

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    run_memory_command(["--cwd", tmp, "inspect", metadata.id, "--session", session_id]),
                    0,
                )
            self.assertIn("CLI inspection fact", output.getvalue())

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(run_memory_command(["--cwd", tmp, "audit"]), 0)
            self.assertIn("remember", output.getvalue())
            self.assertNotIn("CLI inspection fact", output.getvalue())

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    run_memory_command(
                        ["--cwd", tmp, "forget", metadata.id, "--session", session_id, "--yes"]
                    ),
                    0,
                )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    run_memory_command(["--cwd", tmp, "inspect", metadata.id, "--session", session_id]),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
