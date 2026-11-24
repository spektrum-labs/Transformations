"""
Transformation: isBehavioralMonitoringValid
Vendor: Endpoint Protection Platform
Category: Endpoint Security

Windows Defender: reported as not measured (see below).

Windows Defender's definition routes this key to GET /api/alerts. An alert is a detection; it says
nothing about whether behavior monitoring is switched on, and the old `affirmative_signal` turned any
non-empty alert list into a pass. No Defender for Endpoint API wired to this integration reports the
behavior monitoring setting, so the check is not measured on every body.
"""

from datetime import datetime


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBehavioralMonitoringValid",
                "vendor": "Endpoint Protection Platform",
                "category": "Endpoint Security"
            }
        }
    }


KEYS = ("isBehavioralMonitoringValid",)
REASON = ("Windows Defender's alert list (GET /api/alerts) does not evidence behavioral monitoring; "
          "this check is not measured")


def transform(input):
    # Nothing this definition sends can decide the control, so every key is None and the status is
    # derived from that value: not measured, never a pass and never a gap.
    result = {}
    for key in KEYS:
        result[key] = None
    measured = all(result[key] is not None for key in KEYS)
    return create_response(
        result=result,
        validation={"status": "unknown", "errors": [], "warnings": []},
        fail_reasons=[] if measured else [REASON],
        recommendations=["Remove this check from the Windows Defender definition, or source it from a documented configuration assessment"],
        api_errors=[] if measured else [REASON],
    )
