import tempfile
import unittest
from pathlib import Path

from secminiagent.security.scanner import SecurityScanner


class SecurityScannerTest(unittest.TestCase):
    def test_detects_secret_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.py").write_text('API_KEY = "sk-testsecret123456789012345"\n', encoding="utf-8")
            findings = SecurityScanner(cwd=root).scan_secrets()
            self.assertTrue(any(finding.rule_id == "SECRET_OPENAI_KEY" for finding in findings))

    def test_detects_insecure_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            findings = SecurityScanner(cwd=root).scan_insecure_patterns()
            self.assertTrue(any(finding.rule_id == "PY_EVAL_EXEC" for finding in findings))


if __name__ == "__main__":
    unittest.main()
