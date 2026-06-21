import tempfile
import unittest
from pathlib import Path

from secminiagent.agent.loop import AgentLoop
from secminiagent.config import AppConfig
from secminiagent.llm.base import LLMResponse, ToolCall
from secminiagent.llm.fake import FakeLLMClient
from secminiagent.safety.permissions import PermissionManager
from secminiagent.storage.transcript import TranscriptStore
from secminiagent.tools.registry import ToolRegistry
from secminiagent.tools.security_tools import ScanSecretsTool


class AgentLoopTest(unittest.IsolatedAsyncioTestCase):
    async def test_runs_tool_then_final_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.py").write_text('token = "abcdef1234567890"\n', encoding="utf-8")
            client = FakeLLMClient(
                [
                    LLMResponse(
                        content="",
                        tool_calls=[ToolCall("call_1", "scan_secrets", {"path": "."})],
                        assistant_message={
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": "scan_secrets", "arguments": '{"path":"."}'},
                                }
                            ],
                        },
                        raw={},
                    ),
                    LLMResponse(
                        content="Found a hardcoded token.",
                        tool_calls=[],
                        assistant_message={"role": "assistant", "content": "Found a hardcoded token."},
                        raw={},
                    ),
                ]
            )
            registry = ToolRegistry()
            registry.register(ScanSecretsTool())
            loop = AgentLoop(
                client=client,
                registry=registry,
                config=AppConfig.from_values(cwd=str(root), provider="fake", model="fake"),
                session=TranscriptStore(root).create(),
                permission_manager=PermissionManager(interactive=False),
            )
            result = await loop.run("scan secrets")
            self.assertIn("hardcoded token", result.final_text)


if __name__ == "__main__":
    unittest.main()
