"""
Transformation: isContinuousDiscoveryEnabled
Vendor: Egnyte Content Cloud  |  Category: Data Security
Source: GET /pubapi/v2/users
Pass: the user estate is enumerable, with active and inactive accounts distinguishable,
so who can reach the content cloud is inventoried rather than assumed.
"""
import json
from datetime import datetime, timezone


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
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


def _pick(data, *keys):
    """The collection may arrive at a named key, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            value = data.get(k)
            if isinstance(value, list):
                return value
        for k in ("items", "value", "results", "resources"):
            value = data.get(k)
            if isinstance(value, list):
                return value
    return []


def _pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)


def _flag(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def _parse_dt(value):
    if not value or not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(value[:19], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _now():
    return datetime.now(timezone.utc)


def evaluate(data):
    users = _pick(data, "resources", "Resources")
    total = data.get("totalResults") if isinstance(data, dict) else None
    if not isinstance(total, int):
        total = len(users)
    active = [u for u in users if u.get("active")]
    locked = [u for u in users if u.get("locked")]
    by_type = {}
    for u in users:
        by_type[str(u.get("userType"))] = by_type.get(str(u.get("userType")), 0) + 1
    result = {
        "isContinuousDiscoveryEnabled": len(users) > 0,
        "provisionedUserCount": total,
        "usersReturned": len(users),
        "activeUserCount": len(active),
        "inactiveUserCount": len(users) - len(active),
        "lockedUserCount": len(locked),
        "userTypeBreakdown": by_type,
    }
    passes, fails, recs = [], [], []
    if users:
        passes.append(
            "User inventory is readable: %d account(s) returned, %d active."
            % (len(users), len(active))
        )
        if total and len(users) < total:
            recs.append(
                "The response is paginated: %d of %d accounts were returned. Page through "
                "startIndex so the assessment covers the whole estate."
                % (len(users), total)
            )
    else:
        fails.append("No user accounts were returned, so the Egnyte user estate cannot be enumerated.")
    return result, passes, fails, recs, {"usersReturned": len(users), "totalResults": total}


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    result, pass_reasons, fail_reasons, recommendations, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isContinuousDiscoveryEnabled",
            "vendor": "Egnyte",
            "category": "Data Security",
        },
    )
