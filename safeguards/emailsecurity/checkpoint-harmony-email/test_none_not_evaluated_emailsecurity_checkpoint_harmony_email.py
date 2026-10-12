"""A criterion these transforms return as None must reach the evaluator as not evaluated.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is
"error" (which create_response sets only from a non-empty api_errors). Each body below proves
nothing about the estate, so each transform must answer None AND say so. Synthetic data only.
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


ERROR_BODY = {"error": True, "message": "Integration execution error: HTTP 500"}

CASES = [
    ('openquarantinedmessagescount', ('openQuarantinedMessagesCount',), 'poisoned', lambda: Poisoned()),
    ('unverifiedallowpolicycount', ('unverifiedAllowPolicyCount',), 'poisoned', lambda: Poisoned()),
]

# Every other transform in the folder: a poisoned read, an error body and an empty body are all Not
# evaluated. test_checkpoint_harmony_email_error_body_not_evaluated.py holds the full battery.
for fname, fkey in [
    ('confirmedlicensepurchased', 'confirmedLicensePurchased'),
    ('isaccounttakeoverdetectionenabled', 'isAccountTakeoverDetectionEnabled'),
    ('isantiphishingenabled', 'isAntiPhishingEnabled'),
    ('isantivirusverdictengineenabled', 'isAntivirusVerdictEngineEnabled'),
    ('isclicktimeurlrewriteenabled', 'isClickTimeURLRewriteEnabled'),
    ('isclouddataleakpreventionenabled', 'isCloudDataLeakPreventionEnabled'),
    ('isemailsecurityloggingenabled', 'isEmailSecurityLoggingEnabled'),
    ('isimposteremaildetectionenabled', 'isImposterEmailDetectionEnabled'),
    ('islinkedo365accountactive', 'isLinkedO365AccountActive'),
    ('ispostdeliveryquarantineenabled', 'isPostDeliveryQuarantineEnabled'),
    ('isshadowitdiscoveryenabled', 'isShadowITDiscoveryEnabled'),
    ('isspfenforced', 'isSPFEnforced'),
    ('isurlreputationblocklistenforced', 'isURLReputationBlockListEnforced'),
    ('messagemoveaudittrailenabled', 'messageMoveAuditTrailEnabled'),
]:
    CASES.append((fname, (fkey,), 'poisoned', lambda: Poisoned()))
    CASES.append((fname, (fkey,), 'error body', lambda: dict(ERROR_BODY)))
    CASES.append((fname, (fkey,), 'empty body', lambda: {}))


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
