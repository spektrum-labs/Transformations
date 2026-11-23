"""
Transformation: isBehavioralMonitoringValid
Vendor: Arctic Wolf - EDR Endpoint Security (Aurora Endpoint Defense API)
Category: Endpoint Security

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Not measured by this integration. The Arctic Wolf - EDR Endpoint Security definition routes these keys to the
`checkInstalled` method, which has no request defined in that definition (no url, no HTTP
method), so no vendor body ever reaches this file.

The Aurora Device API's `background_detection` (Get devices extended, GET /devices/v2) is
not a substitute: the vendor defines it as true when "the agent is currently running a
background threat detection scan", a moment-in-time activity, not a monitoring setting.
Behavioural protection settings (memory protection, script control) live in the Aurora
Policy API, which this integration does not call.

What this file did before:
`data.get('isBehavioralMonitoringValid', affirmative_signal(data))` -- a field no
Arctic Wolf API sends.

Docs: Aurora Endpoint Defense API, https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api
(retrieved 2026-10-07).
"""

from datetime import datetime

KEYS = ("isBehavioralMonitoringValid",)

REASON = ("Not measured: this integration calls no Aurora endpoint that reports behavioural "
          "monitoring settings (they live in the Policy API)")


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
                "transformationId": "isBehavioralMonitoringValid",
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
