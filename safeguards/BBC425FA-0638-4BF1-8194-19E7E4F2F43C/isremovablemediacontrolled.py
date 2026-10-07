"""
Transformation: isRemovableMediaControlled
Vendor: Arctic Wolf - EDR Endpoint Security (Aurora Endpoint Defense API)
Category: Endpoint Security

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Measurable in principle, not wired. The Aurora Policy API (Get policy,
GET /policies/v2/{policy_id}) publishes `device_control` with a `control_mode` (Block or
FullAccess) per `device_class` (for example USBDrive), which is the setting that evidences
removable-media control. Measuring it needs a definition that lists the policies assigned
to devices and reads each policy, and a transform written against a captured policy body.
Neither exists yet.

The Arctic Wolf - EDR Endpoint Security definition routes these keys to the
`checkInstalled` method, which has no request defined in that definition (no url, no HTTP
method), so no vendor body ever reaches this file.

What this file did before:
`data.get('isRemovableMediaControlled', affirmative_signal(data))` -- a field no
Arctic Wolf API sends.

Docs: Aurora Endpoint Defense API, https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api
(retrieved 2026-10-07).
"""

from datetime import datetime

KEYS = ("isRemovableMediaControlled",)

REASON = ("Not measured: removable-media control lives in the Aurora Policy API (device_control), "
          "which this integration does not call")


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
                "transformationId": "isRemovableMediaControlled",
                "vendor": "Arctic Wolf",
                "category": "Endpoint Security"
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
