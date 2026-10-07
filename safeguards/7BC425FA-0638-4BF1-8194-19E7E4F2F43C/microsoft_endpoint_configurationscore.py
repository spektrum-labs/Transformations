"""hardenedBaselineCompliance for Microsoft Defender for Endpoint (One-Click), from GET /api/configurationScore.

The One-Click workflow for hardenedBaselineCompliance calls getConfigurationScore, whose 200 body is
{"@odata.context": ".../$metadata#ConfigurationScore/$entity", "time": "...", "score": 822.0}
(https://learn.microsoft.com/en-us/defender-endpoint/api/get-device-secure-score). The transform it
ran before (hardenedbaselinecompliance.py) reads an advanced-hunting "Results" summary that this
call never returns, so every tenant read "0" and failed (15 of 15 on 2026-09-29, raw scores 9 to 880).

Value: Microsoft Secure Score for Devices as a whole-number percentage, round(score / 10). The API
reports points on a 0-1000 scale; the Defender portal shows the same number as a percentage.
The pass bar lives in the requirement.

Not evaluated (dataCollection error, value None): an error body, a body without a numeric score, or a
score outside 0-1000.
"""

import json
from datetime import datetime


CRITERIA_KEY = "hardenedBaselineCompliance"
MAX_POINTS = 1000.0


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for attempt in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": list(passed),
                "failReasons": list(failed) + list(errors),
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security",
            },
        },
    }


def measure(data):
    if not isinstance(data, dict) or "error" in data or "PSError" in data:
        raise ValueError("Microsoft did not return a device secure score")
    if "score" not in data:
        raise ValueError("The configurationScore response carries no score field")
    raw = data.get("score")
    if isinstance(raw, bool):
        raise ValueError("The configurationScore score is not a number")
    try:
        points = float(raw)
    except (TypeError, ValueError):
        raise ValueError("The configurationScore score is not a number")
    if points != points or points < 0 or points > MAX_POINTS:
        raise ValueError("The configurationScore score is outside 0-1000")
    return {
        CRITERIA_KEY: int(round(points * 100.0 / MAX_POINTS)),
        "deviceSecureScorePoints": points,
        "deviceSecureScoreMaxPoints": MAX_POINTS,
        "scoreTime": str(data.get("time") or ""),
    }


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        result = measure(data)
        line = (f"Microsoft Secure Score for Devices is {result['deviceSecureScorePoints']:g} of 1000 "
                f"({result[CRITERIA_KEY]}%)")
        summary = dict(result)
        summary["reading"] = line
        return create_response(result, validation, summary=summary)
    except Exception as error:
        return create_response(
            {CRITERIA_KEY: None},
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
