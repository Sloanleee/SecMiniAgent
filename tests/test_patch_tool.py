import tempfile
import unittest
from pathlib import Path

from secminiagent.tools.base import ToolContext
from secminiagent.tools.patch_tool import ApplyPatchTool


PATCH_TEXT = "\n".join(
    [
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -1,1 +1,1 @@",
        "-print('old')",
        "+print('new')",
        "",
    ]
)


class ApplyPatchToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_applies_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app.py"
            target.write_text("print('old')\n", encoding="utf-8")
            result = await ApplyPatchTool().execute({"patch": PATCH_TEXT}, ToolContext(cwd=root, max_output_chars=4000))
            self.assertTrue(result.success)
            self.assertEqual(target.read_text(encoding="utf-8"), "print('new')\n")


if __name__ == "__main__":
    unittest.main()
