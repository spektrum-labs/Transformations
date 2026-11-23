"""
Transformation: isIDPEnabled
Vendor: Arctic Wolf - EDR Endpoint Security (Aurora Endpoint Defense API)
Category: Identity

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Not measurable from the vendor API: the requirement is document-only (L2). The Aurora User API
(Get user, GET /users/v2/{user_id}) returns role, zone, email and login dates for a console
user; no field records single sign-on or an identity provider, and no other Aurora API
resource publishes the console's SSO configuration. The definition also routes this key to
`getIdentityProvider`, a method with no request defined.

What this file did before:
`data.get('isSSOEnabled', affirmative_signal(data))` -- a field no Arctic Wolf API
sends, so the answer was whatever affirmative_signal made of the body.

Docs: Aurora Endpoint Defense API, https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api
(retrieved 2026-10-07).
"""

from datetime import datetime

KEYS = ("isSSOEnabled", "isSSOEnabledMDR")

REASON = ("Not measured: the Arctic Wolf Aurora API publishes no SSO or identity-provider setting "
          "(the User API carries roles, zones and login dates only), so this is document-only evidence")


def create_response(result, api_errors, input_summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if api_errors else "success",
                "errors": api_errors or []
            },
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": [],
                "failReasons": api_errors or [],
                "recommendations": [],
                "additionalFindings": []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isIDPEnabled",
                "vendor": "Arctic Wolf",
                "category": "Identity"
            }
        }
    }


def transform(input):
    # No body can change this answer, so the body is not read: a value that is always None
    # carries its error status with it, on every path including a body whose reads raise.
    result = {}
    for key in KEYS:
        result[key] = None
    return create_response(result, [REASON])
