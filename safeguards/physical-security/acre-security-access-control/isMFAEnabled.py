"""
Transformation: isMFAEnabled
Vendor: acre Access Control  |  Category: Physical Security
Source: GET /api/f/{instanceKey}/users
Pass: every enabled operator account has TwoFactorEnabled set. These are the accounts
that can unlock doors, add credentials and change access levels, so a single-factor
operator is a physical breach path.
"""
import json
import re
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
    """Parse an ISO 8601 timestamp using fromisoformat only.

    strptime is unusable here: it imports _strptime inside CPython, which the
    transformation sandbox blocks, and the ImportError is not a ValueError, so it
    escapes a normal except and fails the whole check. .NET serialises DateTime
    with seven fractional digits and a trailing Z, which older fromisoformat
    rejects, so both are normalised first. Anything still unparseable returns
    None, and callers treat None as not measured.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) > 10 and text[10] == " ":
        text = text[:10] + "T" + text[11:]
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def utc_now():
    return datetime.now(timezone.utc)


def evaluate(data):
    users = pick_list(data, "users", "operators")
    enabled = [u for u in users if not field_value(u, "IsDisabled")]
    with_mfa, without_mfa, unreadable = [], [], []
    for u in enabled:
        value = field_value(u, "TwoFactorEnabled")
        name = field_value(u, "Username", "CommonName") or field_value(u, "Email") or field_value(u, "Key") or "unnamed"
        if value is None:
            unreadable.append(name)
        elif bool(value):
            with_mfa.append(name)
        else:
            without_mfa.append(name)
    measured = len(with_mfa) + len(without_mfa)
    result = {
        "isMFAEnabled": measured > 0 and not without_mfa,
        "mfaCoveragePercentage": pct(len(with_mfa), measured),
        "operatorsEvaluated": measured,
        "operatorsWithoutMfa": without_mfa[:25],
        "operatorsWithoutMfaCount": len(without_mfa),
        "disabledOperatorCount": len(users) - len(enabled),
        "operatorsNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No enabled operator account reported a TwoFactorEnabled value, so operator MFA "
            "could not be measured."
        )
        recs.append("Confirm the API user holds Read on the User object type.")
    elif not without_mfa:
        passes.append(
            "All %d enabled operator account(s) have two-factor authentication enabled."
            % measured
        )
    else:
        fails.append(
            "%d of %d enabled operator account(s) sign in with a password alone: %s. These "
            "accounts can unlock doors and issue credentials."
            % (len(without_mfa), measured, ", ".join(without_mfa[:10]))
        )
        recs.append(
            "Enable two-factor authentication on every operator account, starting with any "
            "account holding door-control or credential-issuance rights."
        )
    return result, passes, fails, recs, {"operatorsEvaluated": measured, "usersReturned": len(users)}


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
            "transformationId": "isMFAEnabled",
            "vendor": "Acre Security",
            "category": "Physical Security",
        },
    )
