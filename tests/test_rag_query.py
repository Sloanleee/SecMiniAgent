import unittest

from secminiagent.rag.query import SUPPORTED_QUERY_STRATEGIES, build_query


class RagQueryTest(unittest.TestCase):
    def test_supported_query_strategies(self):
        self.assertEqual(
            SUPPORTED_QUERY_STRATEGIES,
            ("description_only", "description_port", "description_port_hint"),
        )

    def test_description_only(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_only")

        self.assertEqual(query, "Office host accessed PLC Modbus service.")

    def test_description_port(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_port")

        self.assertEqual(query, "Office host accessed PLC Modbus service. traffic to port 502")

    def test_description_port_hint(self):
        sample = {"description": "Office host accessed PLC Modbus service.", "destination_port": 502}

        query = build_query(sample, "description_port_hint")

        self.assertIn("Office host accessed PLC Modbus service.", query)
        self.assertIn("traffic to port 502", query)
        self.assertIn("Modbus PLC", query)

    def test_unknown_strategy_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "Unknown RAG query strategy"):
            build_query({"description": "x"}, "unknown")


if __name__ == "__main__":
    unittest.main()
