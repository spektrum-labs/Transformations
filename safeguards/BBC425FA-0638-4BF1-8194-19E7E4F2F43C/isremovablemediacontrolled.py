"""
Transformation: isRemovableMediaControlled
Vendor: Halcyon (Endpoint Security)
Category: Endpoint Security

NOT MEASURED. Every key below returns None with a dataCollection error, so it reads Unevaluated
-- never Passed, never Failed.

Halcyon's definition does not route a vendor body that answers this key; not measured.
In the definition the key is wired to the `checkInstalled` method; this file does not read
that response to answer it.

What this file did before:
`data.get('isRemovableMediaControlled', affirmative_signal(data))`, a self-answer from the
body it was judging.
"""

from datetime import datetime

KEYS = ("isRemovableMediaControlled",)

REASON = "Not measured: Halcyon's definition does not route a vendor body that answers this key"


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
                "vendor": "Halcyon",
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
