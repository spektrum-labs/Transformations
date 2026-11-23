"""A criterion these transforms return as None must reach the evaluator as not evaluated.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is
"error" (which create_response sets only from a non-empty api_errors). Each body below proves
nothing about the account, so each transform must answer None AND say so. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("nne_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


CASES = [
    ('exploitedfindingscount', ('exploitedFindingsCount',), 'empty_dict', lambda: {}),
    ('exploitedfindingscount', ('exploitedFindingsCount',), 'poisoned', lambda: Poisoned()),
    ('isasmenabled', ('isASMEnabled',), 'empty_dict', lambda: {}),
    ('isasmenabled', ('isASMEnabled',), 'error_body', lambda: {"error": True, "message": "HTTP 503"}),
    ('isasmenabled', ('isASMEnabled',), 'poisoned', lambda: Poisoned()),
    ('nocriticalfindings', ('noCriticalFindings',), 'empty_dict', lambda: {}),
    ('nocriticalfindings', ('noCriticalFindings',), 'error_body', lambda: {"error": True, "message": "HTTP 503"}),
    ('nocriticalfindings', ('noCriticalFindings',), 'poisoned', lambda: Poisoned()),
    ('nohighfindings', ('noHighFindings',), 'empty_dict', lambda: {}),
    ('nohighfindings', ('noHighFindings',), 'error_body', lambda: {"error": True, "message": "HTTP 503"}),
    ('nohighfindings', ('noHighFindings',), 'poisoned', lambda: Poisoned()),
    ('isasmenabled', ('isASMEnabled',), 'empty_list_no_count', lambda: {"domains": []}),
    ('exploitedfindingscount', ('exploitedFindingsCount',), 'empty_list_contradicting_count',
     lambda: {"vulnerabilities": [], "total_results": 3}),
    ('nocriticalfindings', ('noCriticalFindings',), 'empty_list_contradicting_count',
     lambda: {"risks": [], "total_results": 3}),
    ('nohighfindings', ('noHighFindings',), 'empty_list_contradicting_count',
     lambda: {"risks": [], "total_results": 3}),
    ('isasmenabled', ('isASMEnabled',), 'cut_off_page',
     lambda: {"domains": [{"active": False}], "next_page_token": "abc"}),
    ('exploitedfindingscount', ('exploitedFindingsCount',), 'cut_off_page',
     lambda: {"vulnerabilities": [{"known_exploited_vulnerability": False}], "next_page_token": "abc"}),
    ('nocriticalfindings', ('noCriticalFindings',), 'cut_off_page',
     lambda: {"risks": [{"severity": "low"}], "next_page_token": "abc"}),
    ('nohighfindings', ('noHighFindings',), 'error_beside_records',
     lambda: {"risks": [{"severity": "low"}], "error": "boom"}),
]


class NoneReadsAsNotEvaluated(unittest.TestCase):
    def test_none_carries_a_data_collection_error(self):
        for name, criteria, case, body in CASES:
            with self.subTest(transform=name, body=case):
                out = load(name).transform(body())
                inner = out.get("transformedResponse", out)
                present = [k for k in criteria if k in inner]
                self.assertTrue(present, "no criterion in the output")
                for key in present:
                    self.assertIsNone(inner[key])
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "error")
                self.assertTrue(collection["errors"])
                self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))


if __name__ == "__main__":
    unittest.main()
