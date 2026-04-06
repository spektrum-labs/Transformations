"""
Transformation: confirmedLicensePurchased
Vendor: Splunk
Category: SIEM

Evaluates confirmedLicensePurchased for Splunk SIEM
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Splunk", "category": "SIEM"}
        }
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Splunk licenser endpoint returns entries under entry array
        entries = data.get("entry", data.get("entries", []))
        if not isinstance(entries, list):
            entries = []

        license_count = len(entries)
        license_type = "unknown"
        active_licenses = 0

        for entry in entries:
            content = entry.get("content", entry)
            ltype = content.get("type", content.get("license_type", ""))
            status = content.get("status", "")
            is_active = content.get("is_active", None)

            if ltype:
                license_type = str(ltype)

            if is_active is True or str(status).lower() in ("valid", "active", "ok"):
                active_licenses += 1
            elif is_active is None and "error" not in str(content).lower():
                active_licenses += 1

        result = active_licenses > 0

        return create_response(

            result={
            "confirmedLicensePurchased": result,
            "licenseCount": license_count,
            "activeLicenses": active_licenses,
            "licenseType": license_type
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
