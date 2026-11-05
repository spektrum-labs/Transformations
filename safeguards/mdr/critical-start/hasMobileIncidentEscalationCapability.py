"""Transformation: hasMobileIncidentEscalationCapability - Critical Start MDR (ZTAP), GET {serverUrl}/api/1.5/groups/ (getGroups).

ZTAP escalation groups carry the delivery methods their members are paged on (delivery_methods). A group that
delivers by SMS, phone, voice or mobile push gives the organization a mobile escalation path; one such group proves
it, even on a partial read. False only on a complete read of at least one group where every group delivers by
email (or nothing) alone. No groups, an error body or a partial read with no mobile method is not measured (None).
"""
import json
from datetime import datetime

VENDOR = "Critical Start"
WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, metadata=None, transformation_errors=None, api_errors=None,
                    additional_findings=None):
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


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    if cur.get("errMsg") or cur.get("errNo"):
        return json.dumps(cur.get("errMsg") or cur.get("errNo"))[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the vendor's total and the paginator's truncation flag stay visible.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def truncated(input, box):
    """True when the Integration-Service paginator marked the merged read partial."""
    for cur in (box, raw_body(input), input):
        if isinstance(cur, dict) and cur.get("paginationTruncated") is True:
            return True
    return False


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def read_objects(input, noun):
    """(objects, complete, problem) from a ZTAP list read: {"objects": [...], "total": N, ...}."""
    box, problem = find_key(raw_body(input), "objects")
    if problem is not None:
        return None, False, "Critical Start returned an error instead of " + noun + ": " + problem
    if box is None or not isinstance(box.get("objects"), list):
        return None, False, "No Critical Start " + noun + " list in the response; nothing to evaluate."
    items = [o for o in box["objects"] if isinstance(o, dict)]
    if len(items) != len(box["objects"]):
        return None, False, "The " + noun + " list holds entries that are not records, so it cannot be scored."
    total = to_int(box.get("total"))
    if total is None:
        return None, False, "The " + noun + " list carries no readable total, so a complete read cannot be shown."
    complete = (not truncated(input, box)) and len(items) >= total
    return items, complete, None


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def parse_time(value):
    """ZTAP timestamps are "2026-11-05T21:15:47Z". No strptime: the Token-Service sandbox does not allow it."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    if value[4] != "-" or value[7] != "-" or value[10] not in ("T", " ") or value[13] != ":" or value[16] != ":":
        return None
    try:
        return datetime(int(value[0:4]), int(value[5:7]), int(value[8:10]), int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except Exception:
        return None

MOBILE_METHODS = ("sms", "mms", "text", "phone", "voice", "call", "push", "mobile")


def methods_of(group):
    value = group.get("delivery_methods")
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for m in value:
        if isinstance(m, dict):
            m = m.get("type") or m.get("name") or m.get("method")
        if isinstance(m, str) and m.strip():
            out.append(m.strip().lower())
    return out


def tokens(method):
    return "".join(c if c.isalnum() else " " for c in method).split()


def is_mobile(method):
    """Exact token match ("sms", "mobile_push", "phone call"); "slack_app" or "callback" is not mobile."""
    for word in tokens(method):
        if word in MOBILE_METHODS:
            return True
    return False


def transform(input):
    key = "hasMobileIncidentEscalationCapability"
    validation = extract_validation(input)
    try:
        groups, complete, problem = read_objects(input, "escalation groups")
        if problem is not None:
            return not_measured(key, problem, validation)
        if not groups:
            return not_measured(key, "Critical Start returned no escalation groups, so no escalation path can be shown.", validation)
        all_methods = sorted({m for g in groups for m in methods_of(g)})
        mobile_groups = [g for g in groups if any(is_mobile(m) for m in methods_of(g))]
        if mobile_groups:
            text = (str(len(mobile_groups)) + " of " + str(len(groups)) + " Critical Start escalation groups deliver by a mobile method ("
                    + ", ".join(sorted({m for g in mobile_groups for m in methods_of(g) if is_mobile(m)})) + ").")
            ok = True
        elif complete:
            text = ("All " + str(len(groups)) + " Critical Start escalation groups deliver by " + (", ".join(all_methods) if all_methods else "no method")
                    + " only; no SMS, phone, voice or mobile push escalation is configured.")
            ok = False
        else:
            return not_measured(key, "Only part of the escalation group list was read and none of it delivers by a mobile method; a partial read cannot show that none does.", validation)
        return create_response(
            result={key: ok, "escalationGroupsRead": len(groups), "mobileEscalationGroups": len(mobile_groups)},
            validation=validation,
            pass_reasons=[text] if ok else [],
            fail_reasons=[] if ok else [text],
            recommendations=[] if ok else ["Add an SMS or phone delivery method to at least one ZTAP escalation group (ZTAP > Organization > Escalation groups > Delivery methods)."],
            input_summary={"escalationGroupsRead": len(groups), "deliveryMethods": all_methods, "completeRead": complete},
            metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
        )
    except Exception as e:
        return not_measured(key, "Transformation error: " + str(e), validation)
