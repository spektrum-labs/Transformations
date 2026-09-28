"""
Transformation: adminAccountCount
Vendor: Egnyte Content Cloud  |  Category: Data Security
Source: GET /pubapi/v2/users, reading userType per active account
Measures: how many active accounts hold the Administrator role, and what share of the
estate that is. Administrators can change permissions on any folder and read any file.
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


def pick_list(data, *keys):
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


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)


def field_value(record, *names):
    """Field casing varies between the REST payload and the BSON projection."""
    for n in names:
        if n in record:
            return record[n]
        alt = n[0].lower() + n[1:]
        if alt in record:
            return record[alt]
    return None


def parse_dt(value):
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


def utc_now():
    return datetime.now(timezone.utc)


def evaluate(data):
    users = pick_list(data, "resources", "Resources")
    active = [u for u in users if u.get("active")]
    admins, power, standard, unreadable = [], [], [], []
    for u in active:
        name = u.get("userName") or u.get("email") or str(u.get("id"))
        role = str(u.get("userType") or "").lower()
        if not role or role == "none":
            unreadable.append(name)
        elif role == "admin":
            admins.append(name)
        elif role == "power":
            power.append(name)
        else:
            standard.append(name)
    measured = len(admins) + len(power) + len(standard)
    result = {
        "adminAccountCount": len(admins),
        "adminAccountPercentage": pct(len(admins), measured),
        "activeUsersEvaluated": measured,
        "powerUserCount": len(power),
        "standardUserCount": len(standard),
        "adminAccounts": admins[:25],
        "usersNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append("No active account reported a userType, so the administrator population could not be counted.")
    else:
        passes.append(
            "%d of %d active account(s) hold the Administrator role (%s%%)."
            % (len(admins), measured, result["adminAccountPercentage"])
        )
        if len(admins) == 0:
            recs.append(
                "No active administrator was found. Confirm the token can see admin accounts "
                "before treating this as a clean result."
            )
        elif result["adminAccountPercentage"] and result["adminAccountPercentage"] > 10:
            recs.append(
                "Administrators are %s%% of the active estate. Review whether each needs "
                "domain-wide permission and file access, or whether Power User suffices."
                % result["adminAccountPercentage"]
            )
    return result, passes, fails, recs, {"activeUsersEvaluated": measured},


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
            "transformationId": "adminAccountCount",
            "vendor": "Egnyte",
            "category": "Data Security",
        },
    )
