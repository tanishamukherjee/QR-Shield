"""
QRShield - Backend / Offline Simulation Parity Tests
Runs the shared cases in parity_cases.json through the Python engine.
The same file is checked against the JS offline simulation by frontend/verify_parity.js,
so both engines are held to identical rule IDs and scores.
"""

import sys
import os
import json
import unittest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from url_analyzer import analyze_url

CASES_PATH = os.path.join(os.path.dirname(__file__), "parity_cases.json")


class TestQRShieldParity(unittest.TestCase):

    def test_shared_parity_cases(self):
        """Every shared case must produce the expected rule IDs and score."""
        with open(CASES_PATH, encoding="utf-8") as f:
            cases = json.load(f)["cases"]

        for case in cases:
            with self.subTest(case=case["name"]):
                result = analyze_url(case["url"])
                self.assertEqual([f["rule_id"] for f in result["findings"]], case["expected_rule_ids"])
                self.assertEqual(result["risk_score"], case["expected_score"])


if __name__ == "__main__":
    unittest.main()
