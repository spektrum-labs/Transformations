"""A scan with no result must say why in the stream, and must never read as a pass.

Integration-Service answers {"status": "error", "reason": "asm_scan_in_progress" | "asm_scan_retry_backoff" |
...} while a ProjectDiscovery scan has no stored result. These transforms used to write only
"Nuclei scan status: error", so every such check read as an unexplained failure. Each transform now
appends the reason token to that same text (the prefix is unchanged) and still answers not-true with a
dataCollection error, so Token-Service stores the check as Unevaluated. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

TRANSFORMS = [
    "nuclei_transform", "isasmenabled", "criticalvulnerabilitycount", "knownexploitedvulncount",
    "knownexploitedhighvulncount", "epsshighriskcriticalvulncount", "epsshighriskhighvulncount",
    "externalassetinventorycount", "vulnerabilityscanfrequency", "iscontinuousdiscoveryenabled_scan",
]

IN_PROGRESS = {
    "status": "error",
    "reason": "asm_scan_in_progress",
    "message": "ASM scan not evaluated yet: a full scan of this passport's domain is still running after 60s",
}


def load(name):
    spec = importlib.util.spec_from_file_location("scan_reason_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(name, body):
    out = load(name).transform(body)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]


class ScanReasonInStream(unittest.TestCase):
    def test_the_reason_reaches_the_data_collection_error(self):
        for name in TRANSFORMS:
            for reason in ("asm_scan_in_progress", "asm_scan_retry_backoff", "asm_scan_shared_no_result",
                           "asm_scan_max_duration_exceeded"):
                with self.subTest(transform=name, reason=reason):
                    _, collection = run(name, dict(IN_PROGRESS, reason=reason))
                    self.assertEqual(collection["status"], "error")
                    self.assertEqual(len(collection["errors"]), 1)
                    text = collection["errors"][0]
                    self.assertTrue(text.startswith("Nuclei scan status: error"), text)
                    self.assertTrue(text.endswith("(reason: " + reason + ")"), text)

    def test_a_scan_with_no_result_is_never_a_pass(self):
        for name in TRANSFORMS:
            with self.subTest(transform=name):
                answer, collection = run(name, IN_PROGRESS)
                self.assertEqual(collection["status"], "error")
                for key, value in answer.items():
                    self.assertIsNot(value, True, key)
                    self.assertFalse(isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0,
                                     key + " answered a zero for a scan that never completed")

    def test_no_reason_keeps_the_old_text_exactly(self):
        for name in TRANSFORMS:
            with self.subTest(transform=name):
                _, collection = run(name, {"status": "error", "message": "boom"})
                text = collection["errors"][0]
                self.assertTrue(text.startswith("Nuclei scan status: error"), text)
                self.assertNotIn("reason", text)

    def test_only_a_short_lowercase_token_is_passed_on(self):
        hostile = ["ASM_SCAN_IN_PROGRESS ", "asm scan; DROP", "x" * 61, "a\nb", "<script>", "", None, 7, ["asm_scan_lost"]]
        for name in TRANSFORMS:
            for reason in hostile:
                with self.subTest(transform=name, reason=reason):
                    _, collection = run(name, dict(IN_PROGRESS, reason=reason))
                    text = collection["errors"][0]
                    if isinstance(reason, str) and reason.strip().lower() == "asm_scan_in_progress":
                        self.assertTrue(text.endswith("(reason: asm_scan_in_progress)"), text)
                    elif reason == 7:
                        self.assertTrue(text.endswith("(reason: 7)"), text)
                    else:
                        self.assertNotIn("reason", text)
                        self.assertNotIn("\n", text)


if __name__ == "__main__":
    unittest.main()
