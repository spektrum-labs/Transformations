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
# or invalid key is a 401, not this. The refusal means the log was never read, so the check
# cannot say whether the tenant's log is reachable once the permission is granted: it is
# Unevaluated (value None, data-collection error naming the permission), never False.
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
#
# Verdict: a successful read proves the credential has authentication log access, so it is
# True, including an EMPTY list (a quiet window: v2 reads the last 30 days only) -- but an empty
# list passes only when the body proves success (success_proven: Duo's "stat": "OK" envelope or
# the getAuthLogs returnSpec's authlogs + metadata). An empty list without that proof, an
# error-marked body, a failed enriched validation, Duo's 403 / 40301 refusal, any other
# handed-over vendor error and a body with no log list at all (an error envelope, a bare error
# body, None, non-JSON) are Not evaluated: every key None with a data-collection error. False
# only when records came back and some lack timestamp/factor/result/username (positive evidence).
META = {"transformationId": "hasAuthenticationLogAPIAccess", "vendor": "Duo", "category": "iam"}
ACCESS_FORBIDDEN_CODE = 40301
V1_ENDPOINT = "/admin/v1/logs/authentication"
V2_ENDPOINT = "/admin/v2/logs/authentication"


PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant read log"
REFUSAL_KEYS = ["hasAuthenticationLogAPIAccess", "totalRecords"]
REFUSAL_ENDPOINT = "the Duo authentication log endpoint (" + V1_ENDPOINT + " or " + V2_ENDPOINT + ")"


def refusal_decoded(body):
    """A vendor body or whole input as an object: dicts as they are, JSON text or bytes parsed, else None."""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except Exception:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return None
    return body


def refusal_envelope(value):
    """The dict carrying vendorErrorAsResponse: the input itself or one level inside it, else None."""
    value = refusal_decoded(value)
    if not isinstance(value, dict):
        return None
    if "vendorErrorAsResponse" in value:
        return value
    for k in value:
        inner = value[k]
        if isinstance(inner, dict) and "vendorErrorAsResponse" in inner:
            return inner
    return None


def refusal_unevaluated(envelope, validation=None):
    """Duo's refusal (or any other handed-over vendor error) as Unevaluated: every key None, never False."""
    marker = envelope.get("vendorErrorAsResponse")
    status = marker.get("status") if isinstance(marker, dict) else None
    body = refusal_decoded(marker.get("body")) if isinstance(marker, dict) else None
    forbidden = (status == 403 and isinstance(body, dict)
                 and body.get("code") == ACCESS_FORBIDDEN_CODE and body.get("message") == "Access forbidden")
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    if forbidden:
        problem = ("PERMISSION-NOT-GRANTED: Duo refused the call to " + REFUSAL_ENDPOINT + " with HTTP 403 code 40301 "
                   "(Access forbidden) because the Admin API application lacks the \"" + REQUIRED_PERMISSION
                   + "\" permission. Nothing was measured; this is not a posture result.")
        recommendation = ("In the Duo Admin Panel, open the Admin API application used for Spektrum and enable the \""
                          + REQUIRED_PERMISSION + "\" permission; the integration key and secret do not change.")
    else:
        problem = ("Duo refused the call to " + REFUSAL_ENDPOINT + " (HTTP " + str(status)[:10]
                   + "); nothing was measured.")
        recommendation = "Confirm the Duo Admin API credentials are valid and the Admin API application is enabled."
    out = create_response(
        result=result, validation=validation, fail_reasons=[problem], api_errors=[problem],
        recommendations=[recommendation],
        input_summary={"vendorStatus": status if isinstance(status, int) else None,
                       "vendorCode": body.get("code") if isinstance(body, dict) else None},
        metadata=META,
    )
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        collection["requiredPermission"] = REQUIRED_PERMISSION
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def unreadable(message, validation=None):
    """Nothing was read: every key None with a data-collection error, never False."""
    return create_response(
        result={"hasAuthenticationLogAPIAccess": None, "totalRecords": None},
        validation=validation,
        api_errors=[message],
        metadata=META,
    )


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


def error_marked(body):
    """True when a dict body says it is an error (an Integration-Service envelope, a Duo FAIL body)."""
    if not isinstance(body, dict):
        return False
    stat = body.get("stat")
    status = body.get("status")
    return (body.get("error") not in (None, False) or "errorMessage" in body
            or body.get("success") is False
            or (isinstance(stat, str) and stat.upper() == "FAIL")
            or (isinstance(status, str) and status.lower() == "error"))


def success_proven(raw):
    """True only when the body itself shows Duo answered a log read successfully.

    An empty list is what several failed reads look like (a collection layer defaulting to [],
    an error envelope carrying an empty data list), so an empty read counts as a pass only with
    positive proof: Duo's own {"stat": "OK", "response": ...} envelope (v1, or raw v2), or the
    getAuthLogs returnSpec output {"authlogs": [...], "metadata": {...}}, which Integration-Service
    builds only for a non-error response. A failed enriched validation is never proof."""
    body = raw
    for _ in range(4):
        if not isinstance(body, dict):
            return False
        if error_marked(body):
            return False
        if "data" in body and "validation" in body:
            validation = body.get("validation")
            if isinstance(validation, dict) and validation.get("status") == "failed":
                return False
            body = body.get("data")
            continue
        stat = body.get("stat")
        if isinstance(stat, str) and stat.upper() == "OK" and isinstance(body.get("response"), (list, dict)):
            return True
        if isinstance(body.get("authlogs"), list) and isinstance(body.get("metadata"), dict):
            return True
        moved = False
        for key in ("apiResponse", "api_response", "result", "response"):
            if isinstance(body.get(key), dict):
                body = body[key]
                moved = True
                break
        if not moved:
            return False
    return False


def transform(input):
    try:
        return evaluate(input)
    except Exception:
        return unreadable("The authentication log response could not be processed.")


def evaluate(input):
    refusal = refusal_envelope(input)
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except ValueError:
            input = {}
    data, validation = extract_input(input)
    if refusal is None:
        refusal = refusal_envelope(data)
    if not isinstance(validation, dict):
        validation = None  # create_response substitutes its default
    if refusal is not None:
        # Duo's 403 / 40301 refusal and any other handed-over vendor error are not log data:
        # report them as Unevaluated (the permission named for 40301 only), never judge on them.
        return refusal_unevaluated(refusal, validation)
    if isinstance(validation, dict) and validation.get("status") == "failed":
        return unreadable("Input validation failed; the authentication log body is not evidence", validation)

    endpoint, records, log_metadata = read_auth_logs(data)
    if endpoint is not None and (error_marked(data) or error_marked(input)
                                 or (not records and not success_proven(input))):
        # An error-marked body, or an empty list with nothing showing Duo answered successfully,
        # is not a read: Not evaluated, never a pass from an empty default.
        endpoint = None
    if endpoint is None:
        # No authentication log list at all (an Integration-Service error envelope, a bare Duo
        # error body, None, non-JSON): nothing was read, so nothing is judged.
        return unreadable("The response holds no authentication log list (expected the v1 \"response\" "
                          "list or the v2 \"authlogs\" list): %s" % str(data)[:300], validation)
    endpoint_text = endpoint
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

    # A successful read proves the credential can read the authentication log. An empty list
    # (v2 reads the last 30 days only) is a quiet window, not a refusal: Duo refuses with 403/40301.
    empty_window = total_records == 0
    has_access = empty_window or all(
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

    if has_access and empty_window:
        pass_reasons = [
            f"Duo Admin API {endpoint_text} read OK with an empty window: the credential can read "
            "authentication logs, and Duo returned no authentication events for the requested range "
            "(a refusal would be HTTP 403, code 40301)."
        ]
        fail_reasons = []
        recommendations = []
    elif has_access:
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
