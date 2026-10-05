"""isTamperProtectionEnabled and isRealTimeProtectionEnabled for Microsoft Defender for Endpoint (One-Click),
from the advanced-hunting query over DeviceTvmSecureConfigurationAssessment that the One-Click methods
getTamperProtectionStatus (scid-2010) and getRealTimeProtectionStatus (scid-2011) run.

Why a separate file: istamperprotectionenabled.py / isrealtimeprotectionenabled.py return true when ONE
device is compliant ("protected > 0"), so 1943 of 2075 devices passed "real-time protection is active
on all endpoints"; and they return false when no device is applicable (phones only, or no device
onboarded), a fail with nothing to measure (Orion Steel, ReSRG, Atlas, Pelican on 2026-09-29).

Value: true only when every applicable device is compliant for that SCID; false when at least one
applicable device is not. The compliant share is also returned as a whole-number percentage
(tamperProtectionCompliancePercentage / realTimeProtectionCompliancePercentage).
IsCompliant / IsApplicable arrive as SByte strings ("1", "0", "None") or booleans.

Not evaluated (dataCollection error, values None): an error or unrecognised body, rows for an
unexpected SCID, or no applicable device. This query sees only the assessment table, never the machine
list, so an empty assessment cannot show that Defender for Endpoint protects 0 devices (it may also mean
the assessment has not run); the reason says exactly what the assessment returned and nothing more.
Device coverage, including "0 onboarded devices", is reported by the deployment and coverage checks.
"""

import json
from datetime import datetime


SCIDS = {
    "scid-2010": ("isTamperProtectionEnabled", "tamperProtectionCompliancePercentage", "tamper protection"),
    "scid-2011": ("isRealTimeProtectionEnabled", "realTimeProtectionCompliancePercentage", "real-time protection"),
}


def flag(value):
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in ("1", "true")


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
                "transformationId": "microsoft_endpoint_scid_compliance",
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security",
            },
        },
    }


def empty_result():
    result = {}
    for scid in SCIDS:
        result[SCIDS[scid][0]] = None
        result[SCIDS[scid][1]] = None
    return result


def measure(data):
    if not isinstance(data, dict) or "error" in data or "PSError" in data:
        raise ValueError("Microsoft did not return advanced-hunting results")
    rows = data.get("Results")
    if not isinstance(rows, list) or not isinstance(data.get("Schema"), list):
        raise ValueError("The advanced-hunting response carries no Schema/Results arrays")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("The advanced-hunting response contains an invalid row")
    seen = set(str(row.get("ConfigurationId") or "") for row in rows)
    unknown = seen - set(SCIDS)
    if unknown:
        raise ValueError("Unexpected configuration ids in the results: " + ", ".join(sorted(unknown)))
    result = empty_result()
    counts = {}
    for scid in SCIDS:
        assessed = [row for row in rows if row.get("ConfigurationId") == scid]
        applicable = [row for row in assessed if flag(row.get("IsApplicable"))]
        compliant = [row for row in applicable if flag(row.get("IsCompliant"))]
        counts[scid] = (len(compliant), len(applicable), len(assessed))
        if applicable:
            result[SCIDS[scid][0]] = len(compliant) == len(applicable)
            result[SCIDS[scid][1]] = (len(compliant) * 100) // len(applicable)
    return result, counts


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        result, counts = measure(data)
        passed = []
        failed = []
        for scid in SCIDS:
            if counts[scid][1]:
                line = f"{counts[scid][0]} of {counts[scid][1]} applicable devices have {SCIDS[scid][2]} on ({scid})"
                if counts[scid][0] == counts[scid][1]:
                    passed.append(line)
                else:
                    failed.append(line)
        lines = passed + failed
        errors = []
        if not lines:
            for scid in SCIDS:
                if counts[scid][2]:
                    errors.append("Defender for Endpoint's secure-configuration assessment lists " + str(counts[scid][2])
                                  + " devices for " + SCIDS[scid][2] + " (" + scid + ") and none is applicable, "
                                  "so Defender for Endpoint does not measure " + SCIDS[scid][2] + " here")
            if not errors:
                errors.append("Defender for Endpoint's secure-configuration assessment returned no device for tamper "
                              "protection (scid-2010) or real-time protection (scid-2011), so Defender for Endpoint "
                              "does not measure them here; this query cannot show whether any device is onboarded")
        summary = dict(result)
        summary["readings"] = lines
        return create_response(result, validation, errors=errors, passed=passed, failed=failed, summary=summary)
    except Exception as error:
        return create_response(
            empty_result(),
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
