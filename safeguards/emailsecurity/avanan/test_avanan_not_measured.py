"""Avanan isURLRewriteEnabled and isEmailSecurityLoggingEnabled read Unevaluated on every body.

Both used to answer from a field of their own name, with fallbacks that passed whenever the
endpoint answered at all. The Smart API publishes neither a URL-rewrite nor a logging setting,
and the definition's sec-events/search and audit/logs paths are not in the published API, so
every key must be None with dataCollection.status "error". Synthetic data only.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

FILES = {
    "isurlrewriteenabled": ("isURLRewriteEnabled",),
    "isemailsecurityloggingenabled": ("isEmailSecurityLoggingEnabled", "isEmailLoggingEnabled"),
}


def load(name):
    spec = importlib.util.spec_from_file_location("avanan_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive any except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


BODIES = {
    "empty": lambda: {},
    "none": lambda: None,
    # each of these read True before: an events list (even empty), a non-empty audit list, the key
    "empty-events": lambda: {"securityEvents": [], "apiResponse": {}},
    "audit-logs": lambda: {"auditLogs": [{"id": "a1", "action": "login"}]},
    "self-answer": lambda: {"isURLRewriteEnabled": True, "isEmailSecurityLoggingEnabled": True},
    "error": lambda: {"responseEnvelope": {"responseCode": 401, "responseText": "Unauthorized"}},
    "poisoned": lambda: Poisoned(),
}


@pytest.mark.parametrize("name", sorted(FILES))
@pytest.mark.parametrize("case", sorted(BODIES))
def test_every_key_is_unevaluated(name, case):
    out = load(name).transform(BODIES[case]())
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])
    for key in FILES[name]:
        assert out["transformedResponse"][key] is None
