import unittest

from secminiagent.memory.errors import MemoryValidationError
from secminiagent.memory.normalizer import ContentNormalizer, NormalizationLimits


class ContentNormalizerTest(unittest.TestCase):
    def test_normalizes_unicode_newlines_and_zero_width_characters(self):
        result = ContentNormalizer().normalize("ＰＡＳＳ\u200bＷＯＲＤ\r\nvalue")
        self.assertEqual(result.primary, "PASSWORD\nvalue")

    def test_adds_url_decoded_variant(self):
        result = ContentNormalizer().normalize("token%3Dsk-syntheticabcdefghijklmnop")
        self.assertIn("token=sk-syntheticabcdefghijklmnop", [variant.text for variant in result.variants])

    def test_adds_joined_literal_variant(self):
        result = ContentNormalizer().normalize('value = "sk-" + "syntheticabcdefghijklmnop"')
        self.assertIn("value = sk-syntheticabcdefghijklmnop", [variant.text for variant in result.variants])

    def test_extracts_nested_json_string_with_depth_bound(self):
        result = ContentNormalizer().normalize('{"outer":{"password":"Synthet1c-Only-Value"}}')
        self.assertIn("Synthet1c-Only-Value", [variant.text for variant in result.variants])

    def test_decodes_bounded_base64_candidate(self):
        result = ContentNormalizer().normalize("cGFzc3dvcmQgPSAiU3ludGhldDFjLU9ubHktVmFsdWUi")
        self.assertIn('password = "Synthet1c-Only-Value"', [variant.text for variant in result.variants])

    def test_rejects_oversized_input(self):
        normalizer = ContentNormalizer(NormalizationLimits(max_input_chars=10))
        with self.assertRaises(MemoryValidationError):
            normalizer.normalize("x" * 11)


if __name__ == "__main__":
    unittest.main()
