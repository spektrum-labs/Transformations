"""Transformation: isControllerOnline - acre Access Control (Physical Security), GET /api/f/{instanceKey}/controllers.

True only on a complete read of the controllers list where at least one controller is enabled (IsDisabled not true) and every
enabled controller reports Status.IsOnline true. One enabled controller reporting offline is always False. An error body, a
list with no enabled controller, a partial read, or an enabled controller that carries no Status.IsOnline value behind an
otherwise clean read is not measured (None).
"""
import json
from datetime import datetime

VENDOR = "Acre Security"
WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "Physical Security"},
    )


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("Message") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_controllers(input):
    """(controllers, problem, truncated): the list of controller records, through any wrapper, or why there is none."""
    cur = input.get("data") if isinstance(input, dict) and "validation" in input else input
    truncated = False
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, truncated
        if isinstance(cur, list):
            return cur, None, truncated
        if not isinstance(cur, dict):
            return None, None, truncated
        if cur.get("paginationTruncated") is True or cur.get("truncated") is True:
            truncated = True
        if isinstance(cur.get("controllers"), list):
            return cur["controllers"], None, truncated
        problem = error_in(cur)
        if problem is not None:
            return None, problem, truncated
        nxt = None
        for wrapper in WRAPPERS:
            if isinstance(cur.get(wrapper), (dict, list, str)):
                nxt = cur.get(wrapper)
                break
        if nxt is None:
            return None, None, truncated
        cur = nxt
    return None, None, truncated


def field_value(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def transform(input):
    key = "isControllerOnline"
    validation = extract_validation(input)
    controllers, problem, truncated = find_controllers(input)
    if problem is not None:
        return not_measured(key, "acre returned an error instead of the controller list: " + problem, validation)
    if controllers is None:
        return not_measured(key, "No acre controller list in the response; nothing to evaluate.", validation)
    records = [c for c in controllers if isinstance(c, dict)]
    if len(records) != len(controllers):
        return not_measured(key, "The controller list holds entries that are not controller records, so it cannot be scored.", validation)
    if truncated:
        return not_measured(key, "Read stopped at the page limit (" + str(len(records)) + " controllers); a partial read is not scored.", validation)
    enabled = [c for c in records if field_value(c, "IsDisabled") is not True]
    if not enabled:
        return not_measured(key, "acre lists no enabled controller, so there is no panel to judge.", validation)
    online = []
    offline = []
    unreadable = 0
    for c in enabled:
        status = field_value(c, "Status")
        value = field_value(status, "IsOnline") if isinstance(status, dict) else None
        if value is True:
            online.append(c)
        elif value is False:
            offline.append(str(field_value(c, "CommonName") or field_value(c, "Key") or "unnamed")[:80])
        else:
            unreadable = unreadable + 1
    if not offline and unreadable > 0:
        return not_measured(key, str(unreadable) + " enabled controller(s) carry no Status.IsOnline value, so all-online cannot be shown.", validation)
    ok = not offline
    text = (str(len(online)) + " of " + str(len(enabled)) + " enabled controllers are online with the communication service.")
    return create_response(
        result={key: ok, "enabledControllerCount": len(enabled), "onlineControllerCount": len(online), "offlineControllerCount": len(offline),
                "offlineControllers": offline[:25], "controllersNotMeasured": unreadable},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text + " Doors on an offline controller still open from its cached database but its reads are not reported."],
        recommendations=[] if ok else ["Restore communications to the offline controllers, then reconcile the door events buffered during the outage."],
        input_summary={"enabledControllerCount": len(enabled), "offlineControllerCount": len(offline)},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "Physical Security"},
    )
