import os
import tempfile
import unittest
from pathlib import Path

from secminiagent.config import AppConfig, default_model, default_provider, load_dotenv, parse_dotenv_line


class ConfigTest(unittest.TestCase):
    def tearDown(self):
        for key in [
            "SECMINI_PROVIDER",
            "SECMINI_MODEL",
            "OPENAI_API_KEY",
            "XFYUN_API_KEY",
            "XFYUN_MODEL",
        ]:
            os.environ.pop(key, None)

    def test_parse_dotenv_line(self):
        self.assertEqual(parse_dotenv_line("SECMINI_PROVIDER=fake"), ("SECMINI_PROVIDER", "fake"))
        self.assertEqual(parse_dotenv_line('export SECMINI_MODEL="demo"'), ("SECMINI_MODEL", "demo"))
        self.assertIsNone(parse_dotenv_line("# comment"))

    def test_load_dotenv_preserves_existing_env(self):
        os.environ["SECMINI_PROVIDER"] = "from-env"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("SECMINI_PROVIDER=from-file\nSECMINI_MODEL=test-model\n", encoding="utf-8")
            loaded = load_dotenv(path)
        self.assertIn("SECMINI_MODEL", loaded)
        self.assertEqual(os.environ["SECMINI_PROVIDER"], "from-env")
        self.assertEqual(os.environ["SECMINI_MODEL"], "test-model")

    def test_defaults_to_fake_without_keys(self):
        self.assertEqual(default_provider(), "fake")
        self.assertEqual(default_model("fake"), "fake-security-model")

    def test_xfyun_env_selects_provider_and_model(self):
        os.environ["XFYUN_API_KEY"] = "key"
        os.environ["XFYUN_MODEL"] = "model-id"
        self.assertEqual(default_provider(), "xfyun")
        self.assertEqual(default_model("xfyun"), "model-id")
        self.assertEqual(AppConfig.from_values(cwd=".").provider, "xfyun")


if __name__ == "__main__":
    unittest.main()
