"""Every Anthropic AI transform, against every route to a non-answer, in one matrix.

Token-Service grades a criterion unless additionalInfo.dataCollection.status is "error". The
value is never consulted. So a transform that cannot measure must return None AND say so, and
a test that asserts only one of the two passes on a file that does the other -- which is how
the hardcoded status and the missing api_errors in this directory both survived review.

There are at least three independent routes to a non-answer and a file can pass one while
failing another, so this runs all of them rather than picking a representative:

  * the vendor's own error envelope, {"error": {"type", "message"}}, verbatim from
    platform.claude.com/docs/en/manage-claude/compliance-errors -- four status classes;
  * Integration-Service's relay envelope, which is the shape /integration/run actually hands
    a transform when the vendor refuses;
  * an AWS-shaped envelope with a capital E, which Anthropic will never send and which is here
    precisely because a recogniser written against one vendor's shape silently misses another's;
  * bodies with nothing in them -- {}, [], [{}], None, "{}", {"status": "Not Available"};
  * a POISONED body, a dict whose every read raises, which is the only way to reach the branch
    inside transform()'s own except. No body, however malformed, enters that branch.

Discovery is by directory listing, not by a list in this file: a transform added tomorrow is
covered without anyone remembering to add it. Synthetic data only.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

# Temporary, and meant to be deleted rather than maintained. iscomplianceapienabled.py is
# being rewritten in flight by PR #931 (feat(anthropic): Claude Compliance API criteria), so
# it is left exactly as main has it to avoid a conflict. It carries the same defect as its
# siblings and this change does NOT fix it; whoever reviews #931 owns confirming the refusal,
# empty and poisoned paths there. Remove this set once #931 lands -- the matrix then covers
# that file, and the three transforms #931 adds, without anyone editing a list.
OWNED_BY_ANOTHER_PR = {"iscomplianceapienabled"}

TRANSFORMS = sorted(f[:-3] for f in os.listdir(HERE)
                    if f.endswith(".py") and not f.startswith("test_")
                    and f[:-3] not in OWNED_BY_ANOTHER_PR)


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


# Verbatim from the vendor's error reference, which states the contract as "a JSON body with
# an error object containing type and message" and instructs callers to match on the status
# code and error.type, never on the message string.
VENDOR_403 = {"error": {"type": "permission_error",
                        "message": "Missing required scopes. Got: ['read:compliance_activities'] "
                                   "Needed one of: ['read:compliance_user_data', 'read:org_audit']"}}
VENDOR_401 = {"error": {"type": "authentication_error", "message": "invalid x-api-key"}}
VENDOR_404 = {"error": {"type": "not_found_error", "message": "Not found"}}
VENDOR_429 = {"error": {"type": "rate_limit_error",
                        "message": "Compliance API rate limit of 600 requests per minute per "
                                   "parent organization has been exceeded."}}
RELAY_403 = {"integrationName": "Anthropic", "errorMessage": "Forbidden",
             "vendorStatus": 403, "vendorError": "permission_error"}
AWS_SHAPED = {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}

NO_EVIDENCE = {
    "empty_dict": lambda: {},
    "empty_list": lambda: [],
    "list_of_empty": lambda: [{}],
    "list_of_two_empty": lambda: [{}, {}],
    "not_available": lambda: {"status": "Not Available"},
    "none": lambda: None,
    "empty_json_string": lambda: "{}",
    "vendor_403": lambda: dict(VENDOR_403),
    "vendor_401": lambda: dict(VENDOR_401),
    "vendor_404": lambda: dict(VENDOR_404),
    "vendor_429": lambda: dict(VENDOR_429),
    "relay_403": lambda: dict(RELAY_403),
    "aws_shaped_403": lambda: dict(AWS_SHAPED),
    "poisoned": Poisoned,
}

# The one documented exception, and it is an exception to the body shape, not to the rule.
# Both key transforms distinguish "no key list came back" (not measured) from "a key list came
# back and it was empty" (no standing credential exists, so nothing can be non-expiring or
# stale). That pass is deliberate, is reasoned in the files, and requires a list to have been
# READ -- which an empty list was. It is pinned here so that removing it has to be a decision.
EMPTY_LIST_PASSES = {"iscredentialexpirationenforced", "isstalecredentialsremoved"}


MATRIX = [(name, shape) for name in TRANSFORMS for shape in sorted(NO_EVIDENCE)
          if not (shape == "empty_list" and name in EMPTY_LIST_PASSES)]


@pytest.mark.parametrize("name,shape", MATRIX)
def test_no_evidence_reaches_the_evaluator_as_not_evaluated(name, shape):
    module = load(name)
    out = module.transform(NO_EVIDENCE[shape]())
    inner = out.get("transformedResponse", out)
    assert module.CRITERION in inner, "the file did not answer its own criterion key"
    assert inner[module.CRITERION] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert all(isinstance(e, str) and e for e in collection["errors"])


@pytest.mark.parametrize("name", sorted(EMPTY_LIST_PASSES))
def test_the_empty_list_pass_is_still_reachable_and_still_says_so(name):
    """The negative control for the rule above: this one body is a pass, on purpose."""
    out = load(name).transform([])
    assert out["transformedResponse"][load(name).CRITERION] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]


# ---------------------------------------------------------------------------------------
# The other two replays. A file that answers None to everything is not a check either.
# Rows have the shape the live effective-settings endpoint returns: {name, type, value}.
# ---------------------------------------------------------------------------------------

def rows(**values):
    return [{"name": k, "type": "boolean", "value": v} for k, v in values.items()]


DISCRIMINATES = [
    ("isssorequired", True, rows(sso_enabled=True, sso_claude_ai_enforced=True, sso_console_enforced=True)),
    ("isssorequired", False, rows(sso_enabled=True, sso_claude_ai_enforced=True, sso_console_enforced=False)),
    ("ismodeltrainingdatausedisabled", True, rows(frontier_data_use_enabled=False)),
    ("ismodeltrainingdatausedisabled", False, rows(frontier_data_use_enabled=True)),
    ("iscontentredactionenabled", True, rows(content_redaction_enabled=True)),
    ("iscontentredactionenabled", False, rows(content_redaction_enabled=False)),
    ("isagenttelemetryenabled", True, rows(claude_code_metrics_logging_enabled=True)),
    ("isagenttelemetryenabled", False, rows(claude_code_metrics_logging_enabled=False)),
    ("isextensionallowlistenforced", True, rows(desktop_extension_allowlist_enabled=True)),
    ("isextensionallowlistenforced", False, rows(desktop_extension_allowlist_enabled=False)),
    ("isthirdpartycontentrestricted", True, rows(third_party_interactive_content_enabled=False)),
    ("isthirdpartycontentrestricted", False, rows(third_party_interactive_content_enabled=True)),
    # Inverted key, and this is the only one in the directory: isCodeExecutionNetworkEgressEnabled
    # reports the EGRESS state, so True is the insecure answer and False is the pass. Pinned
    # both ways round so a future reader cannot "correct" it into agreement with its siblings.
    ("iscodeexecutionnetworkegressenabled", False,
     rows(code_execution_enabled=True, code_execution_network_egress_enabled=False)),
    ("iscodeexecutionnetworkegressenabled", True,
     rows(code_execution_enabled=True, code_execution_network_egress_enabled=True)),
    ("isipallowlistenabled", False, rows(ip_allowlist_enabled=False)),
    ("isscimprovisioningenabled", False, rows(directory_sync_enabled=False)),
]


@pytest.mark.parametrize("name,expected,body", DISCRIMINATES)
def test_a_read_setting_is_still_measured(name, expected, body):
    """Both answers stay reachable, and a measured answer keeps the success status.

    This is the half of the change that must NOT move. Turning every unmeasured path into
    None is only an improvement if the measured paths still answer; a check that can only
    say "not evaluated" has stopped being a check.
    """
    module = load(name)
    out = module.transform(body)
    assert out["transformedResponse"][module.CRITERION] is expected
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_the_vendor_scope_message_reaches_the_customer():
    """Anthropic's 403 carries no statusCode, so the 403 guidance used to never fire on it.

    The tailored paragraph tells an administrator the endpoint needs a Compliance Access Key
    and that an Admin API key gets 403 here -- which is the single most common cause of this
    integration going dark. Before, that body produced only "the vendor call did not succeed".
    """
    out = load("isssorequired").transform(dict(VENDOR_403))
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"]
                    + out["additionalInfo"]["evaluation"]["recommendations"])
    assert "Compliance Access Key" in text
    assert "Missing required scopes" in text
