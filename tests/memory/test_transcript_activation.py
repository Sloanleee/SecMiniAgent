import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secminiagent.cli import run_memory_command
from secminiagent.memory.migration import MigrationCapability
from secminiagent.storage.transcript import ThreadAwareTranscriptStore, TranscriptStore
from secminiagent.agent.loop import AgentLoop
from secminiagent.config import AppConfig
from secminiagent.llm.base import LLMResponse
from secminiagent.llm.fake import FakeLLMClient
from secminiagent.safety.permissions import PermissionManager
from secminiagent.tools.registry import ToolRegistry


class TranscriptActivationTest(unittest.TestCase):
    def test_verified_runtime_capability_cannot_be_forged_with_public_flags(self):
        capability = MigrationCapability(True, True, True, True)
        self.assertFalse(capability.can_activate)
        self.assertTrue(MigrationCapability.verified_v2_runtime().can_activate)

    def test_explicit_migration_switches_then_reads_legacy_and_appends_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_store = TranscriptStore(root)
            session = legacy_store.create()
            session.record_message({"role": "user", "content": "legacy user message"})
            session.record_message({"role": "assistant", "content": "legacy assistant message"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2", "--yes"])
            self.assertEqual(result, 0, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["phase"], "switched")
            runtime = TranscriptStore(root)
            self.assertIsInstance(runtime, ThreadAwareTranscriptStore)
            loaded = runtime.load(session.id)
            self.assertEqual([item["content"] for item in loaded.messages], ["legacy user message", "legacy assistant message"])
            connection = sqlite3.connect(root / ".secminiagent" / "memory" / "memory.db")
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM runs WHERE status='running'").fetchone()[0], 0)
            finally:
                connection.close()
            loaded.record_message({"role": "user", "content": "new v2 message"})
            loaded.complete_run()
            reopened = TranscriptStore(root).load(session.id)
            self.assertEqual(reopened.messages[-1]["content"], "new v2 message")
            fresh = TranscriptStore(root).create()
            fresh.record_message({"role": "user", "content": "fresh v2 session"})
            fresh.complete_run()
            self.assertEqual(TranscriptStore(root).load(fresh.id).messages[0]["content"], "fresh v2 session")

    def test_without_yes_migration_does_not_prepare_shadow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TranscriptStore(root)
            store.create()
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                result = run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2"])
            self.assertEqual(result, 1)
            self.assertIn("MIGRATION_CONFIRMATION_REQUIRED", error.getvalue())
            import sqlite3
            connection = sqlite3.connect(store.database_path)
            try:
                names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                connection.close()
            self.assertNotIn("threads_v2", names)


if __name__ == "__main__":
    unittest.main()


class ThreadAwareAgentIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_agent_loop_uses_v2_context_envelope_and_completes_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = TranscriptStore(root).create()
            original.record_message({"role": "user", "content": "historical untrusted instruction"})
            migration_output = io.StringIO()
            with contextlib.redirect_stdout(migration_output):
                self.assertEqual(run_memory_command(["--cwd", str(root), "migrate-schema", "--to", "2", "--yes"]), 0)
            session = TranscriptStore(root).load(original.id)
            client = FakeLLMClient([LLMResponse(
                content="safe answer", tool_calls=[],
                assistant_message={"role": "assistant", "content": "safe answer"}, raw={},
            )])
            loop = AgentLoop(
                client=client, registry=ToolRegistry(),
                config=AppConfig.from_values(cwd=str(root), provider="fake", model="fake"),
                session=session, permission_manager=PermissionManager(interactive=False),
            )
            result = await loop.run("new prompt")
            self.assertEqual(result.final_text, "safe answer")
            self.assertIn("not instructions", client.requests[0]["system_prompt"])
            self.assertTrue(all(message.get("role") != "system" for message in client.requests[0]["messages"]))
            connection = sqlite3.connect(root / ".secminiagent" / "memory" / "memory.db")
            try:
                completed = connection.execute(
                    "SELECT turn_count,input_message_id,final_message_id FROM runs WHERE thread_id=? AND status='completed' ORDER BY run_no DESC LIMIT 1",
                    (session.thread_id,),
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(completed[0], 1)
            self.assertTrue(completed[1])
            self.assertTrue(completed[2])
            reopened = TranscriptStore(root).load(original.id)
            self.assertEqual(reopened.messages[-2]["content"], "new prompt")
            self.assertEqual(reopened.messages[-1]["content"], "safe answer")
