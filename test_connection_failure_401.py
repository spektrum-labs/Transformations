"""
LABS-3035 — reproduction / characterization test for the 401-as-red defect.

Epic: LABS-3034 (integration connection/auth failures must surface as a distinct
non-scoring "grey" state, not silently fail safeguards red).

THE DEFECT
----------
During safeguard evaluate, when a vendor API call returns an authentication /
connection error (most commonly HTTP 401 — bad/expired credentials), the error
response body is handed straight to the safeguard's ``transform()``. The
transform inspects only its expected data keys and never looks at the HTTP
status, so a 401 body (which contains none of those keys) falls through to
``value: False`` and the safeguard is rendered RED — indistinguishable from a
genuine compliance failure.

Observed in production for customer Impelix: every Microsoft safeguard went red
on 2026-05-16, all returning 401 (OAuth token / admin-consent expiry). It went
undetected for ~6 weeks because nothing distinguishes "we can't authenticate to
your tenant" from "your security control failed."

WHAT THIS TEST DOES (per the LABS-3035 acceptance criteria)
-----------------------------------------------------------
This is the "irrefutable problem" record. It mocks a 401 from a Microsoft
safeguard's integration and asserts the CURRENT (wrong) behavior: the transform
returns ``isPrivilegedIdentityManagementEnabled = False`` (red) with no
connection-failure signal whatsoever. These assertions PASS today.

When the sibling fix tickets land (LABS-3036 evaluate-runner detects the failure
before transform; the transform-guard / state-contract tickets emit a distinct
"grey" connection_failure state), this test is the regression guard that gets
flipped to expect grey + unchanged posture. The ``test_post_fix_*`` case below is
marked ``expectedFailure`` and documents that target — the fix ticket removes the
marker.

No third-party deps: the transform module is loaded by path via importlib (the
same mechanism ``local_tester.py`` uses), so this runs under plain stdlib
``unittest`` (pytest / requests / pydantic are not installed in CI for this repo).
It lives at the repo root rather than under ``tests/`` because ``tests/`` is
git-ignored in this repository.

Run:
    cd transformations && python3 -m unittest test_connection_failure_401 -v
"""

import importlib.util
import os
import unittest


# Exact safeguard cited in the ticket: Microsoft IAM / Privileged Identity
# Management — one of the Impelix safeguards that went red on 401.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
TRANSFORM_PATH = os.path.join(
    REPO_ROOT,
    "safeguards",
    "iam",
    "microsoft",
    "isprivilegedidentitymanagementenabled.py",
)
CRITERIA_KEY = "isPrivilegedIdentityManagementEnabled"


def _load_transform(path):
    """Load a transformation module by file path (mirrors local_tester.py)."""
    module_name = os.path.basename(path).replace(".py", "")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- Mock vendor payloads ----------------------------------------------------

# A Microsoft Graph 401 body, exactly as the vendor returns it when the OAuth
# token has expired / admin consent was revoked. Note: none of the keys the
# transform looks for (pamEnabled, privilegedAccounts, enabled, vaults, ...) are
# present — that is the whole problem.
GRAPH_401_BODY = {
    "error": {
        "code": "InvalidAuthenticationToken",
        "message": "Access token has expired or is not yet valid.",
        "innerError": {
            "date": "2026-05-16T00:00:00",
            "request-id": "00000000-0000-0000-0000-000000000000",
        },
    }
}

# An OAuth-handshake failure surfaced as an error envelope (matches the example
# in safeguards/common/response_helper.parse_api_error). Some integrations hand
# the transform a wrapper like this rather than the raw Graph body.
OAUTH_401_ENVELOPE = {
    "error": (
        "OAuth token request failed: Response status code does not indicate "
        "success: 401 (Unauthorized)."
    ),
    "statusCode": 401,
}

# A genuinely healthy response, used as a control so we can prove the false
# `False` above is caused by the 401 — not by a broken test harness.
HEALTHY_BODY = {"pamEnabled": True, "privilegedAccounts": ["admin@impelix.com"]}


class ConnectionFailure401Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Store the module (not the function) so attribute access doesn't bind
        # transform() as a method and pass `self` as a spurious first arg.
        cls._module = _load_transform(TRANSFORM_PATH)

    def transform(self, payload):
        return self._module.transform(payload)

    # ------------------------------------------------------------------
    # CURRENT (WRONG) BEHAVIOR — these assertions pass today and are the
    # regression guard the fix tickets will flip.
    # ------------------------------------------------------------------
    def test_graph_401_is_rendered_red_not_grey(self):
        """A Graph 401 body is scored as a hard compliance failure (red)."""
        result = self.transform(GRAPH_401_BODY)

        # value: False  ->  the safeguard renders RED, indistinguishable from a
        # real control failure. THIS IS THE BUG.
        self.assertIn(CRITERIA_KEY, result)
        self.assertFalse(
            result[CRITERIA_KEY],
            "DEFECT (LABS-3035): a 401 auth failure is reported as value:False "
            "(red) instead of a non-scoring connection_failure / grey state.",
        )

        # The transform is status-blind: nothing in the output signals that this
        # was a connection/auth failure rather than a measured non-compliance.
        self._assert_no_connection_failure_signal(result)

    def test_oauth_401_envelope_is_rendered_red_not_grey(self):
        """An OAuth 401 error envelope is likewise scored red, status ignored."""
        result = self.transform(OAUTH_401_ENVELOPE)

        self.assertIn(CRITERIA_KEY, result)
        self.assertFalse(
            result[CRITERIA_KEY],
            "DEFECT (LABS-3035): the transform ignores statusCode:401 and the "
            "'401 (Unauthorized)' error text, returning value:False (red).",
        )
        self._assert_no_connection_failure_signal(result)

    def test_healthy_response_is_true_control(self):
        """Control: a valid payload returns True, proving the harness is sound."""
        result = self.transform(HEALTHY_BODY)
        self.assertTrue(
            result.get(CRITERIA_KEY),
            "Sanity check failed: a healthy payload should evaluate True — the "
            "false 'False' in the 401 cases must be caused by the 401, not the "
            "test setup.",
        )

    # ------------------------------------------------------------------
    # TARGET (POST-FIX) BEHAVIOR — documents the desired contract. Marked
    # expectedFailure because the fix has not landed yet; the sibling fix
    # ticket (LABS-3036 et al.) removes this marker and the test above's
    # `assertFalse` flips to assert a grey / connection_failure state.
    # ------------------------------------------------------------------
    @unittest.expectedFailure
    def test_post_fix_graph_401_signals_connection_failure(self):
        """Once fixed: a 401 must NOT be value:False; it must signal grey."""
        result = self.transform(GRAPH_401_BODY)

        # After the fix the safeguard must not be scored as a compliance failure.
        self.assertNotEqual(
            result.get(CRITERIA_KEY),
            False,
            "Post-fix: a 401 must not render the safeguard red.",
        )
        # ...and it must carry an explicit connection-failure signal.
        self.assertTrue(
            self._has_connection_failure_signal(result),
            "Post-fix: a 401 must emit a distinct connection_failure / grey "
            "signal so posture scoring can exclude it.",
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _has_connection_failure_signal(result):
        """True if the result carries any explicit connection/auth-failure marker."""
        signal_keys = (
            "connection_failure",
            "connectionFailure",
            "connection_status",
            "connectionStatus",
            "status_code",
            "statusCode",
            "isConnectionFailure",
            "grey",
        )
        if any(k in result for k in signal_keys):
            return True
        # A "grey"/"connection_failure" status value anywhere in the result.
        status_val = str(result.get("status", "")).lower()
        return status_val in ("grey", "gray", "connection_failure")

    def _assert_no_connection_failure_signal(self, result):
        self.assertFalse(
            self._has_connection_failure_signal(result),
            "DEFECT (LABS-3035): the transform produced no connection-failure "
            "signal for a 401 — a broken integration is silently scored as a "
            "failed control. The fix must add this signal.",
        )


if __name__ == "__main__":
    unittest.main()
