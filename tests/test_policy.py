import unittest

from secminiagent.safety.command_policy import CommandAction, CommandPolicy


class CommandPolicyTest(unittest.TestCase):
    def test_blocks_git_reset_hard(self):
        decision = CommandPolicy().classify("git reset --hard HEAD")
        self.assertEqual(decision.action, CommandAction.DENY)

    def test_asks_for_package_install(self):
        decision = CommandPolicy().classify("python -m pip install requests")
        self.assertEqual(decision.action, CommandAction.ASK)

    def test_allows_unittest(self):
        decision = CommandPolicy().classify("python -m unittest")
        self.assertEqual(decision.action, CommandAction.ALLOW)


if __name__ == "__main__":
    unittest.main()
