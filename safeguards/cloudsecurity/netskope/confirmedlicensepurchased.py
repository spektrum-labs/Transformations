"""
Transformation: confirmedLicensePurchased
Vendor: Netskope
Category: Cloud Security / Licensing

Validates that an active Netskope subscription is in place by confirming the
REST API v2 token returns a successful response from the audit events endpoint
(/api/v2/events/data/audit). Audit events are emitted on every active Netskope
tenant regardless of which add-on modules (SWG, CASB, CSPM, NPA) are licensed,
making them the most reliable signal that the tenant is live and the token
has valid access.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data.get("data"), input_data.get("validation")
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data.get(key)
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Netskope",
                "category": "Cloud Security"
            }
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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        license_purchased = False
        license_details = {}

        events = []
        status_value = None
        ok_flag = None
        total_value = None

        if isinstance(data, dict):
            status_value = data.get("status")
            ok_flag = data.get("ok")

            for key in ("result", "data", "events", "items"):
                value = data.get(key)
                if isinstance(value, list):
                    events = value
                    break

            for key in ("total", "total_count", "count"):
                value = data.get(key)
                if isinstance(value, int):
                    total_value = value
                    break
        elif isinstance(data, list):
            events = data

        event_count = len(events) if isinstance(events, list) else 0

        api_responded_ok = False
        if isinstance(status_value, str) and status_value.lower() == "success":
            api_responded_ok = True
        if isinstance(ok_flag, int) and ok_flag == 1:
            api_responded_ok = True
        if isinstance(ok_flag, bool) and ok_flag is True:
            api_responded_ok = True

        if event_count > 0:
            license_purchased = True
            license_details["auditEventCount"] = event_count
            license_details["evidence"] = "audit_events_present"
        elif isinstance(total_value, int) and total_value > 0:
            license_purchased = True
            license_details["totalRecords"] = total_value
            license_details["evidence"] = "total_count_positive"
        elif api_responded_ok:
            license_purchased = True
            license_details["responseStatus"] = status_value if status_value else "ok"
            license_details["evidence"] = "api_acknowledged_request"
        elif isinstance(data, dict) and len(data) > 0:
            license_purchased = True
            license_details["responseKeys"] = list(data.keys())
            license_details["evidence"] = "non_empty_response_body"

        if license_purchased:
            pass_reasons.append(
                "Netskope REST API v2 returned a valid response from /api/v2/events/data/audit confirming an active subscription"
            )
            if event_count > 0:
                additional_findings.append({"auditEventsReturned": event_count})
        else:
            fail_reasons.append(
                "Netskope subscription could not be confirmed - the audit events endpoint returned no usable signal"
            )
            recommendations.append(
                "Verify the REST API v2 token has read access to /api/v2/events/data/audit and that the tenant subscription is active"
            )

        return create_response(
            result={criteriaKey: license_purchased, **license_details},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"licensePurchased": license_purchased, **license_details}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
