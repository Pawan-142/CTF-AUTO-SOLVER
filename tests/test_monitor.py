import copy
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ctfou.monitor import load_state, new_message, run_once, solved_message
from ctfou.solver import Finding


class FakeClient:
    def __init__(self, items, details=None):
        self.items = items
        self.details = details or {}
        self.details_called = []
        self.downloads = []

    def challenges(self):
        return copy.deepcopy(self.items)

    def challenge(self, id_):
        self.details_called.append(str(id_))
        return copy.deepcopy(self.details[str(id_)])

    def attachment(self, path):
        self.downloads.append(path)
        return b"No flag here"


class FakeNotifier:
    def __init__(self):
        self.messages = []

    def send(self, msg):
        self.messages.append(msg)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.item = {"id": 42, "name": "Four Digits Later", "category": "Crypto", "value": 250}
        self.detail = {**self.item, "description": "Find the flag.", "files": []}
        self.client = FakeClient([self.item], {"42": self.detail})
        self.notifier = FakeNotifier()
        self.state = {"schema_version": 1, "initialized": False, "challenges": {}}
        self.when = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)

    def test_baselines_existing_challenges_without_notifications(self):
        with patch.dict(os.environ, {"SOLVE_EXISTING_ON_FIRST_RUN": "false"}):
            run_once(self.client, self.notifier, self.state, timestamp=self.when)
        self.assertEqual(self.notifier.messages, [])
        self.assertEqual(self.client.details_called, [])
        self.assertEqual(self.state["challenges"]["42"]["status"], "baseline")

    def test_new_challenge_name_flag_and_explanation(self):
        self.state["initialized"] = True
        def fake_solver(detail, client):
            return Finding("THMH{test_answer}", "Decoded from hex", "extracted")
        run_once(self.client, self.notifier, self.state, solver=fake_solver, timestamp=self.when)
        self.assertEqual(len(self.notifier.messages), 2)
        self.assertTrue(all("Four Digits Later" in m for m in self.notifier.messages))
        self.assertIn("THMH{test_answer}", self.notifier.messages[1])
        self.assertIn("Decoded from hex", self.notifier.messages[1])
        self.assertIn("not submitted", self.notifier.messages[1])
        self.assertEqual(self.state["challenges"]["42"]["status"], "found")
        # A second scheduled run won't repeat existing challenge alerts.
        run_once(self.client, self.notifier, self.state, solver=fake_solver, timestamp=self.when + timedelta(minutes=10))
        self.assertEqual(len(self.notifier.messages), 2)

    def test_unsolved_retry_after_cooldown(self):
        self.state["initialized"] = True
        run_once(self.client, self.notifier, self.state, solver=lambda *_: None, timestamp=self.when)
        self.assertEqual(len(self.client.details_called), 1)
        run_once(self.client, self.notifier, self.state, solver=lambda *_: None, timestamp=self.when + timedelta(minutes=10))
        self.assertEqual(len(self.client.details_called), 1)
        run_once(self.client, self.notifier, self.state, solver=lambda *_: None, timestamp=self.when + timedelta(hours=6, minutes=1))
        self.assertEqual(len(self.client.details_called), 2)
        self.assertEqual(len(self.notifier.messages), 1)

    def test_ai_guess_marked_as_unverified(self):
        self.assertIn("NOT verified", solved_message(self.detail, Finding("THMH{guess}", "AI inference", "ai_candidate")))

    def test_question_name_in_new_message(self):
        self.assertIn("Question: Four Digits Later", new_message(self.item))

    def test_never_submits_flags(self):
        self.state["initialized"] = True
        run_once(self.client, self.notifier, self.state, solver=lambda *_: None, timestamp=self.when)
        self.assertTrue(self.client.details_called)
        self.assertFalse(hasattr(self.client, "submit_flag"))


if __name__ == "__main__":
    unittest.main()
