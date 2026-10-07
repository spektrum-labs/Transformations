"""
Transformation: isSSOEnabled
Vendor: Egnyte Content Cloud  |  Category: Data Security
Source: GET /pubapi/v2/users, reading authType per account
Pass: every active account authenticates through SAML SSO or Active Directory. An
account with authType 'egnyte' holds a local password outside the corporate identity
provider, so offboarding in the IdP does not close it.
"""
import json
import re
from datetime import datetime, timezone

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isSSOEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


FEDERATED = {"sso", "ad"}


def rows_short_of_total(data, rows):
    """True when the body reports more users than it carries.

    GET /pubapi/v2/users returns at most 100 users per call with totalResults for the
    whole domain. A verdict over one page is a verdict over part of the estate, so a
    short read is not measured rather than judged.
    """
    if not isinstance(data, dict):
        return False
    total = data.get("totalResults")
    return isinstance(total, int) and not isinstance(total, bool) and total > len(rows)


def evaluate(data):
    users = pick_list(data, "resources", "Resources")
    active = [u for u in users if u.get("active")]
    federated, local, unreadable = [], [], []
    for u in active:
        name = u.get("userName") or u.get("email") or str(u.get("id"))
        auth = u.get("authType")
        if auth is None:
            unreadable.append(name)
        elif str(auth).lower() in FEDERATED:
            federated.append(name)
        else:
            local.append(name)
    measured = len(federated) + len(local)
    result = {
        "isSSOEnabled": measured > 0 and not local,
        "ssoCoveragePercentage": pct(len(federated), measured),
        "activeUsersEvaluated": measured,
        "localAuthUserCount": len(local),
        "localAuthUsers": local[:25],
        "usersNotMeasured": unreadable,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No active account reported an authType, so federated authentication could not "
            "be measured."
        )
    elif not local:
        passes.append(
            "All %d active account(s) authenticate through SAML SSO or Active Directory."
            % measured
        )
    else:
        fails.append(
            "%d of %d active account(s) hold a local Egnyte password rather than "
            "authenticating through the identity provider: %s."
            % (len(local), measured, ", ".join(local[:10]))
        )
        recs.append(
            "Migrate the listed accounts to SSO or AD authentication so identity-provider "
            "offboarding closes Egnyte access too."
        )
    if rows_short_of_total(data, users):
        result["isSSOEnabled"] = None
        passes = []
        fails = [
            "The response reports %d users but carries %d, so only part of the domain was "
            "read. Federated authentication is not measured on a partial read."
            % (data.get("totalResults"), len(users))
        ]
        recs = ["Page through startIndex so every user is read."]
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
            "transformationId": "isSSOEnabled",
            "vendor": "Egnyte",
            "category": "Data Security",
        },
    )
