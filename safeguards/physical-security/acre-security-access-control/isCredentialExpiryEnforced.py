"""
Transformation: isCredentialExpiryEnforced
Vendor: acre Access Control  |  Category: Physical Security
Source: GET /api/f/{instanceKey}/people, reading CardAssignments[]
Pass: every enabled card assignment carries a future ExpiresOn date. A credential with
no expiry outlives the person's need for it.
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
    people = _pick(data, "people", "persons")
    now = _now()
    with_expiry, without_expiry, expired = [], [], []
    total_cards = 0
    for p in people:
        person = _flag(p, "CommonName") or _flag(p, "GivenName") or _flag(p, "Key") or "unnamed"
        cards = _flag(p, "CardAssignments") or []
        if not isinstance(cards, list):
            continue
        for card in cards:
            if not isinstance(card, dict) or _flag(card, "IsDisabled"):
                continue
            total_cards += 1
            label = "%s/%s" % (person, _flag(card, "DisplayCardNumber") or _flag(card, "Key") or "card")
            raw = _flag(card, "ExpiresOn")
            parsed = _parse_dt(raw) if raw else None
            if parsed is None:
                without_expiry.append(label)
            elif parsed < now:
                expired.append(label)
            else:
                with_expiry.append(label)
    measured = total_cards
    result = {
        "isCredentialExpiryEnforced": measured > 0 and not without_expiry and not expired,
        "credentialExpiryCoveragePercentage": _pct(len(with_expiry), measured),
        "activeCredentialCount": measured,
        "credentialsWithoutExpiryCount": len(without_expiry),
        "expiredActiveCredentialCount": len(expired),
        "credentialsWithoutExpiry": without_expiry[:25],
        "expiredActiveCredentials": expired[:25],
        "peopleEvaluated": len(people),
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
