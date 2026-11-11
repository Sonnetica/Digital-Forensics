"""Check that the evaluator scores logical messages when copies are preserved."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("etrace_evaluate", ROOT / "evaluation" / "evaluate.py")
evaluate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate_module)


def raw(message_id, *, mailbox, parent=None, subject="Plan"):
    message = EmailMessage()
    message["From"] = "alice@example.org"
    message["To"] = "bob@example.org"
    message["Date"] = "Mon, 12 Oct 2026 09:00:00 +0000"
    message["Subject"] = subject
    message["Message-ID"] = message_id
    message["X-Mailbox"] = mailbox
    if parent:
        message["In-Reply-To"] = parent
    message.set_content("Please confirm the schedule for the Tuas dock doors this week.")
    return message.as_bytes()


class EvaluateTests(unittest.TestCase):
    def _copy_dataset(self, folder):
        files = {
            "parent-sent.eml": raw("<p@example.org>", mailbox="sent"),
            "parent-inbox.eml": raw("<p@example.org>", mailbox="inbox"),
            "child.eml": raw("<c@example.org>", mailbox="inbox", parent="<p@example.org>", subject="Re: Plan"),
        }
        for name, data in files.items():
            (folder / name).write_bytes(data)
        return files

    def test_conflicting_labels_after_copy_grouping_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            folder = Path(directory)
            files = self._copy_dataset(folder)
            rules = ("attachment_reuse", "url_reuse", "reply", "possible_coordination")
            truth = {
                "schema_version": 2,
                "rule_version": "1.1.0",
                "tier": "conflict-test",
                "seed": 1,
                "expected_parameters": {},
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "relationships": {rule: [] for rule in rules}
                | {"reply": [["parent-inbox.eml", "child.eml"]]},
                # The Sent copy is the same message, so this negative contradicts the positive.
                "negative_relationships": {rule: [] for rule in rules}
                | {"reply": [["parent-sent.eml", "child.eml"]]},
                "complete_for": {rule: list(files) for rule in rules},
                "scope": "test",
            }
            (folder / "ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "parent-sent.eml.*child.eml"):
                evaluate_module.evaluate(folder)

    def test_reply_labelled_against_any_copy_scores_once(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            folder = Path(directory)
            files = self._copy_dataset(folder)
            truth = {
                "schema_version": 1,
                "rule_version": "1.1.0",
                "tier": "copy-test",
                "seed": 1,
                "expected_parameters": {},
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "relationships": {
                    "attachment_reuse": [],
                    "url_reuse": [],
                    # Labelled against the Inbox copy; the engine represents the group by one copy.
                    "reply": [["parent-inbox.eml", "child.eml"]],
                    "possible_coordination": [],
                },
                "scope": "test",
            }
            (folder / "ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")
            result = evaluate_module.evaluate(folder)
            self.assertEqual(result["scoring_unit"], "logical_message")
            self.assertEqual(result["logical_messages"], 2)
            self.assertEqual(result["copy_groups"], [["parent-inbox.eml", "parent-sent.eml"]])
            reply = result["per_rule"]["reply"]
            self.assertEqual((reply["tp"], reply["fp"], reply["fn"]), (1, 0, 0))
            self.assertEqual(result["micro"]["fp"] + result["micro"]["fn"], 0)
            self.assertIn("reply", result["file_level_per_rule"])


if __name__ == "__main__":
    unittest.main()
