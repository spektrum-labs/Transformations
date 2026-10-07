import json
from datetime import datetime, timezone


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


# Duo answers GET /admin/v1/logs/authentication and /admin/v2/logs/authentication with
#   403 {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
# when the Admin API application is not granted "Grant read log" (Duo Admin API
# docs: 403 = "This integration is not authorized for this endpoint"). A revoked
# or invalid key is a 401, not this. So this 403 is the answer to the question
# "does the API credential have authentication log access": no.
# Integration-Service hands that one refusal over as data only when the method
# opts in (vendorErrorAsResponse), nested as
#   {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}
#
# Two success shapes reach this transform, depending on which method the definition maps:
#   v1 getAuthenticationLogs  GET /admin/v1/logs/authentication
#       {"stat": "OK", "response": [{"timestamp", "username", "factor", "result", "device", ...}]}
#       Oldest first from mintime; with no mintime, the earliest events Duo retains.
#   v2 getAuthLogs            GET /admin/v2/logs/authentication (mintime now-30d, sort ts:desc)
#       {"authlogs": [{"timestamp", "user": {"name"}, "factor", "result", "txid", ...}],
#        "metadata": {"next_offset": ..., "total_objects": {...}}}
#       (the raw v2 body nests the same under "response"; extract_input unwraps it)
# Both are read the same way; the evidence names the endpoint the data came from and the
# real time span of the records read.
ACCESS_FORBIDDEN_CODE = 40301
V1_ENDPOINT = "/admin/v1/logs/authentication"
V2_ENDPOINT = "/admin/v2/logs/authentication"


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


def read_auth_logs(data):
    """(endpoint, records, metadata) for a v1 or v2 authentication log body; records [] when none."""
    if isinstance(data, dict) and isinstance(data.get("response"), dict) \
            and isinstance(data["response"].get("authlogs"), list):
        data = data["response"]  # raw v2 body that no wrapper unwrapped (e.g. inside enriched "data")
    if isinstance(data, dict) and isinstance(data.get("authlogs"), list):
        metadata = data.get("metadata")
        return V2_ENDPOINT, data["authlogs"], metadata if isinstance(metadata, dict) else {}
    if isinstance(data, list):
        return V1_ENDPOINT, data, {}
    if isinstance(data, dict):
        records = data.get("response")
        if records is None:
            records = data.get("data")
        if isinstance(records, list):
            return V1_ENDPOINT, records, {}
    return None, [], {}


def record_username(rec):
    """v1 carries "username"; v2 carries "user": {"name": ...}."""
    name = rec.get("username")
    if name in (None, ""):
        user = rec.get("user")
        if isinstance(user, dict):
            name = user.get("name")
    return name


def record_epoch(rec):
    """Epoch seconds of one record (v1 and v2 both send `timestamp` in seconds), else None."""
    ts = rec.get("timestamp")
    if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0:
        return float(ts)
    if isinstance(ts, str) and ts.strip().isdigit():
        return float(ts.strip())
    iso = rec.get("isotimestamp")
    if isinstance(iso, str) and iso.strip():
        text = iso.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (ValueError, OverflowError, TypeError):
            return None
    return None


def iso_of(epoch_seconds):
    try:
        return datetime.fromtimestamp(epoch_seconds, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def time_span(records):
    """(oldest ISO, newest ISO) over the records that carry a timestamp; (None, None) when none do."""
    oldest = None
    newest = None
    for rec in records:
        if not isinstance(rec, dict):
            continue
        ts = record_epoch(rec)
        if ts is None:
            continue
        if oldest is None or ts < oldest:
            oldest = ts
        if newest is None or ts > newest:
            newest = ts
    if oldest is None:
        return None, None
    return iso_of(oldest), iso_of(newest)


def span_text(oldest, newest):
    if oldest is None:
        return "no record carries a timestamp"
    if oldest == newest:
        return "all at " + str(newest)
    return "from " + str(oldest) + " to " + str(newest)


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
                "Duo refused the Admin API authentication logs endpoint with HTTP 403, code 40301 "
                "\"Access forbidden\": the Admin API application is not granted read access to "
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

    endpoint, records, log_metadata = read_auth_logs(data)
    endpoint_text = endpoint or "the authentication logs endpoint"
    total_records = len(records)

    required_fields = ["timestamp", "factor", "result", "username"]
    fields_present_counts = {f: 0 for f in required_fields}
    device_field_count = 0
    sample_events = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        values = {
            "timestamp": rec.get("timestamp"),
            "factor": rec.get("factor"),
            "result": rec.get("result"),
            "username": record_username(rec),
        }
        for f in required_fields:
            if values[f] not in (None, ""):
                fields_present_counts[f] = fields_present_counts[f] + 1
        if "device" in rec or "auth_device" in rec or "access_device" in rec:
            device_field_count = device_field_count + 1
        if len(sample_events) < 3:
            sample_events.append(values)

    has_access = total_records > 0 and all(
        fields_present_counts.get(f, 0) == total_records for f in required_fields
    )
    oldest, newest = time_span(records)
    more_available = bool(log_metadata.get("next_offset")) if endpoint == V2_ENDPOINT else None

    input_summary = {
        "endpoint": endpoint,
        "totalRecords": total_records,
        "fieldsPresentCounts": fields_present_counts,
        "deviceFieldCount": device_field_count,
        "oldestRecordTimestamp": oldest,
        "newestRecordTimestamp": newest,
    }
    if endpoint == V2_ENDPOINT:
        input_summary["moreRecordsAvailable"] = more_available

    findings = []
    if endpoint == V1_ENDPOINT and total_records > 0:
        findings.append("Duo v1 returns authentication events oldest first, so these records are the "
                        "earliest in the requested range, not necessarily recent activity.")
    if endpoint == V2_ENDPOINT and more_available:
        findings.append("Duo v2 reported more records after this page (newest first); the span covers "
                        "the records read.")

    if has_access:
        pass_reasons = [
            f"Duo Admin API {endpoint_text} returned {total_records} authentication event records "
            f"{span_text(oldest, newest)}, each containing timestamp, factor, result, and username "
            f"(100% populated across all {total_records} records).",
            f"Sample events include: {sample_events}",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_records == 0:
            fail_reasons = [
                f"The authentication logs endpoint ({endpoint_text}) returned zero records, "
                "so no centralized authentication event trail could be confirmed."
            ]
            recommendations = [
                "Verify the API credential has permission to read authentication logs and that the tenant "
                "has authentication activity in the queried window."
            ]
        else:
            fail_reasons = [
                f"The authentication logs endpoint ({endpoint_text}) returned {total_records} records "
                f"{span_text(oldest, newest)}, but not all records carried the expected fields "
                f"(timestamp, factor, result, username). Field presence counts: {fields_present_counts}."
            ]
            recommendations = [
                "Investigate why some authentication log records are missing required fields; confirm the API "
                "version and endpoint are the documented logs/authentication route."
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
        additional_findings=findings,
        metadata={
            "transformationId": "hasAuthenticationLogAPIAccess",
            "vendor": "Duo",
            "category": "iam",
        },
    )
