"""
Transformation: staleOperatorAccountCount
Vendor: acre Access Control  |  Category: Physical Security
Source: GET /api/f/{instanceKey}/users
Measures: enabled operator accounts that have not signed in for 90 days, or have never
signed in. A dormant operator account is an unreviewed key to the building.
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


STALE_DAYS = 90


def evaluate(data):
    users = _pick(data, "users", "operators")
    enabled = [u for u in users if not _flag(u, "IsDisabled")]
    now = _now()
    stale, active, never, unreadable = [], [], [], []
    for u in enabled:
        name = _flag(u, "Username", "CommonName") or _flag(u, "Email") or _flag(u, "Key") or "unnamed"
        raw = _flag(u, "LastLoginOn") or _flag(u, "LastActivityOn")
        if raw is None:
            unreadable.append(name)
            continue
        parsed = _parse_dt(raw)
        if parsed is None:
            never.append(name)
            continue
        age_days = (now - parsed).days
        if age_days > STALE_DAYS:
            stale.append({"operator": name, "lastLoginDaysAgo": age_days})
        else:
            active.append(name)
    measured = len(stale) + len(active) + len(never)
    stale_total = len(stale) + len(never)
    result = {
        "staleOperatorAccountCount": stale_total,
        "operatorsEvaluated": measured,
        "activeOperatorCount": len(active),
        "neverSignedInOperatorCount": len(never),
        "staleOperatorPercentage": _pct(stale_total, measured),
        "staleOperators": stale[:25],
        "operatorsNotMeasured": unreadable,
        "stalenessThresholdDays": STALE_DAYS,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append("No enabled operator reported a last-login timestamp, so dormancy could not be measured.")
    elif stale_total == 0:
        passes.append(
            "All %d enabled operator account(s) have signed in within %d days."
            % (measured, STALE_DAYS)
        )
    else:
        fails.append(
            "%d of %d enabled operator account(s) have not signed in for over %d days "
            "(%d have never signed in)." % (stale_total, measured, STALE_DAYS, len(never))
        )
        recs.append(
            "Review and disable dormant operator accounts. An account that has never signed "
            "in should be removed rather than left provisioned."
        )
    return result, passes, fails, recs, {"operatorsEvaluated": measured},


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
            "transformationId": "staleOperatorAccountCount",
            "vendor": "Acre Security",
            "category": "Physical Security",
        },
    )
