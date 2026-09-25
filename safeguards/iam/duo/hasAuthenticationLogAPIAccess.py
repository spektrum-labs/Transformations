import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


# Duo answers GET /admin/v1/logs/authentication with
#   403 {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
# when the Admin API application is not granted "Grant read log" (Duo Admin API
# docs: 403 = "This integration is not authorized for this endpoint"). A revoked
# or invalid key is a 401, not this. So this 403 is the answer to the question
# "does the API credential have authentication log access": no.
# Integration-Service hands that one refusal over as data only when the method
# opts in (vendorErrorAsResponse), nested as
#   {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}
ACCESS_FORBIDDEN_CODE = 40301


def duo_access_forbidden(data):
    """True only for Integration-Service's marked 403 / 40301 "Access forbidden" refusal."""
    if not isinstance(data, dict):
        return False
    marker = data.get("vendorErrorAsResponse")
    if not isinstance(marker, dict) or marker.get("status") != 403:
        return False
    body = marker.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return False
    if not isinstance(body, dict):
        return False
    return body.get("code") == ACCESS_FORBIDDEN_CODE and body.get("message") == "Access forbidden"


def transform(input):
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except ValueError:
            input = {}
    data, validation = extract_input(input)
    if duo_access_forbidden(data):
        # A measured FAIL, not an error: Duo answered the question.
        return create_response(
            result={"hasAuthenticationLogAPIAccess": False, "totalRecords": 0},
            validation=validation,
            fail_reasons=[
                "Duo refused the authentication logs endpoint (/admin/v1/logs/authentication) with HTTP 403, "
                "code 40301 \"Access forbidden\": the Admin API application is not granted read access to "
                "authentication logs."
            ],
            recommendations=[
                "In the Duo Admin Panel, open the Admin API application used for Spektrum and enable the "
                "\"Grant read log\" permission."
            ],
            input_summary={"vendorStatus": 403, "vendorCode": ACCESS_FORBIDDEN_CODE},
            metadata={"transformationId": "hasAuthenticationLogAPIAccess", "vendor": "Duo", "category": "iam"},
        )
    if isinstance(data, dict) and "vendorErrorAsResponse" in data:
        # Any other handed-over vendor error is not log data: report it, do not judge on it.
        return create_response(
            result={"hasAuthenticationLogAPIAccess": False, "totalRecords": 0},
            validation=validation,
            api_errors=["Duo returned an error instead of authentication log data: %s"
                        % str(data.get("vendorErrorAsResponse"))[:300]],
            metadata={"transformationId": "hasAuthenticationLogAPIAccess", "vendor": "Duo", "category": "iam"},
        )
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("response")
        if records is None:
            records = data.get("data") or []
    else:
        records = []

    if not isinstance(records, list):
        records = []

    total_records = len(records)

    required_fields = ["timestamp", "factor", "result", "username"]
    fields_present_counts = {f: 0 for f in required_fields}
    device_field_count = 0
    sample_events = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        for f in required_fields:
            if f in rec and rec.get(f) not in (None, ""):
                fields_present_counts[f] = fields_present_counts[f] + 1
        if "device" in rec:
            device_field_count = device_field_count + 1
        if len(sample_events) < 3:
            sample_events.append({
                "username": rec.get("username"),
                "factor": rec.get("factor"),
                "result": rec.get("result"),
                "timestamp": rec.get("timestamp"),
            })

    has_access = total_records > 0 and all(
        fields_present_counts.get(f, 0) == total_records for f in ["timestamp", "factor", "result", "username"]
    )

    input_summary = {
        "totalRecords": total_records,
        "fieldsPresentCounts": fields_present_counts,
        "deviceFieldCount": device_field_count,
    }

    if has_access:
        pass_reasons = [
            f"Duo Admin API v2 authentication logs endpoint returned {total_records} authentication event records, "
            f"each containing timestamp, factor, result, and username fields (100% populated across all {total_records} records).",
            f"Sample events include: {sample_events}",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_records == 0:
            fail_reasons = [
                "The authentication logs endpoint (/admin/v1/logs/authentication) returned zero records, "
                "so no centralized authentication event trail could be confirmed."
            ]
            recommendations = [
                "Verify the API credential has permission to read authentication logs and that the tenant "
                "has authentication activity in the queried window."
            ]
        else:
            fail_reasons = [
                f"The authentication logs endpoint returned {total_records} records, but not all records carried "
                f"the expected fields (timestamp, factor, result, username). Field presence counts: {fields_present_counts}."
            ]
            recommendations = [
                "Investigate why some authentication log records are missing required fields; confirm the API "
                "version and endpoint are the documented v1 logs/authentication route."
            ]

    result = {
        "hasAuthenticationLogAPIAccess": has_access,
        "totalRecords": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasAuthenticationLogAPIAccess",
            "vendor": "Duo",
            "category": "iam",
        },
    )
