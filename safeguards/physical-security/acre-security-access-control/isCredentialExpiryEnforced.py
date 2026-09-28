"""
Transformation: isCredentialExpiryEnforced
Vendor: acre Access Control  |  Category: Physical Security
Source: GET /api/f/{instanceKey}/people, reading CardAssignments[]
Pass: every enabled card assignment carries a future ExpiresOn date. A credential with
no expiry outlives the person's need for it.
"""
import json
import re
from datetime import datetime, timezone, timedelta


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
    people = pick_list(data, "people", "persons")
    now = utc_now()
    # ExpiresOn is a non-nullable .NET DateTime, so "never expires" is stored as a
    # sentinel - DateTime.MinValue or a far-future date such as MaxValue. acre's own
    # reports treat anything beyond UtcNow.AddYears(25) as not a real expiry; so do we.
    horizon = now + timedelta(days=365 * 25 + 6)
    with_expiry, without_expiry, expired, unreadable = [], [], [], []
    sentinel_count = 0
    total_cards = 0
    for p in people:
        person = field_value(p, "CommonName") or field_value(p, "GivenName") or field_value(p, "Key") or "unnamed"
        cards = field_value(p, "CardAssignments") or []
        if not isinstance(cards, list):
            continue
        for card in cards:
            if not isinstance(card, dict) or field_value(card, "IsDisabled"):
                continue
            total_cards += 1
            label = "%s/%s" % (person, field_value(card, "DisplayCardNumber") or field_value(card, "Key") or "card")
            raw = field_value(card, "ExpiresOn")
            if not raw:
                without_expiry.append(label)
                continue
            parsed = parse_dt(raw)
            if parsed is None:
                unreadable.append(label)
            elif parsed.year <= 1 or parsed > horizon:
                without_expiry.append(label)
                sentinel_count = sentinel_count + 1
            elif parsed < now:
                expired.append(label)
            else:
                with_expiry.append(label)
    measured = total_cards - len(unreadable)
    result = {
        "isCredentialExpiryEnforced": measured > 0 and not without_expiry and not expired,
        "credentialExpiryCoveragePercentage": pct(len(with_expiry), measured),
        "activeCredentialCount": measured,
        "credentialsWithoutExpiryCount": len(without_expiry),
        "expiredActiveCredentialCount": len(expired),
        "credentialsWithoutExpiry": without_expiry[:25],
        "expiredActiveCredentials": expired[:25],
        "peopleEvaluated": len(people),
        "neverExpiringSentinelCount": sentinel_count,
        "credentialsNotMeasured": unreadable[:25],
        "expiryHorizonYears": 25,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No enabled card assignment was returned, so credential expiry could not be "
            "measured."
        )
        recs.append("Confirm the API user holds Read on the Person type and that cards are assigned.")
    elif not without_expiry and not expired:
        passes.append(
            "All %d enabled credential(s) carry a future expiry date." % measured
        )
    else:
        fails.append(
            "%d enabled credential(s) have no expiry date and %d have expired but remain "
            "enabled, out of %d."
            % (len(without_expiry), len(expired), measured)
        )
        recs.append(
            "Set an expiry on every issued credential, and disable the credentials whose "
            "expiry has already passed."
        )
    return result, passes, fails, recs, {"activeCredentialCount": measured, "peopleEvaluated": len(people)},


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
            "transformationId": "isCredentialExpiryEnforced",
            "vendor": "Acre Security",
            "category": "Physical Security",
        },
    )
