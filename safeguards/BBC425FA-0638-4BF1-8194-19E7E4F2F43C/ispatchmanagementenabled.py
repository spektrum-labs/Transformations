"""
Transformation: isPatchManagementEnabled
Vendor: Arctic Wolf - EDR Endpoint Security (Aurora Endpoint Defense API)
Category: Patch Management

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Not measurable from the vendor API: the requirement is document-only (L2) for this
integration. Aurora Endpoint Security is endpoint protection. No Aurora Endpoint Defense API
resource (User, Device, Global list, Policy, Zone, Threat, Memory protection, Detections,
Package deployment, Device commands, Lockdown configurations) reports operating-system or
application patch state or a patching policy.

The Arctic Wolf - EDR Endpoint Security definition routes these keys to the
`checkInstalled` method, which has no request defined in that definition (no url, no HTTP
method), so no vendor body ever reaches this file.

What this file did before:
`data.get('isPatchManagementEnabled', affirmative_signal(data))` and the same for
isPatchManagementValid -- fields no Arctic Wolf API sends.

Docs: Aurora Endpoint Defense API, https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api
(retrieved 2026-10-07).
"""

from datetime import datetime

KEYS = ("isPatchManagementEnabled", "isPatchManagementValid")

REASON = ("Not measured: Arctic Wolf Aurora is endpoint protection and its API reports no patch "
          "management state, so this is document-only evidence for this integration")


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
                "transformationId": "isPatchManagementEnabled",
                "vendor": "Arctic Wolf",
                "category": "Patch Management"
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
