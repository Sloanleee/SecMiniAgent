import unittest

from secminiagent.rag.evaluator import hit_rate, mrr, recall_at_k


class RagEvaluatorTest(unittest.TestCase):
    def test_recall_at_k(self):
        results = [["protocol_modbus", "playbook"], ["wrong"]]
        expected = [{"protocol_modbus"}, {"missing"}]

        self.assertEqual(recall_at_k(results, expected, k=2), 0.5)

    def test_recall_at_k_counts_fraction_of_expected_documents(self):
        results = [["protocol_modbus"], ["playbook", "wrong"]]
        expected = [{"protocol_modbus", "s7comm"}, {"playbook", "incident_response"}]

        self.assertEqual(recall_at_k(results, expected, k=1), 0.5)

    def test_mrr(self):
        results = [["wrong", "protocol_modbus"], ["playbook"]]
        expected = [{"protocol_modbus"}, {"playbook"}]

        self.assertAlmostEqual(mrr(results, expected), 0.75)

    def test_hit_rate(self):
        results = [["wrong", "protocol_modbus"], ["playbook"]]
        expected = [{"protocol_modbus"}, {"missing"}]

        self.assertEqual(hit_rate(results, expected, k=2), 0.5)

    def test_hit_rate_remains_binary_when_recall_is_fractional(self):
        results = [["protocol_modbus"], ["wrong"]]
        expected = [{"protocol_modbus", "s7comm"}, {"missing"}]

        self.assertEqual(hit_rate(results, expected, k=1), 0.5)


if __name__ == "__main__":
    unittest.main()
