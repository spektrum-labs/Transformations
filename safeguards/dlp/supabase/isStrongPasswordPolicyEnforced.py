"""
Transformation: isStrongPasswordPolicyEnforced
Vendor: Supabase  |  Category: Data Security
Source: GET /v1/projects/{ref}/config/auth, fanned out across projects
Pass: every project with email sign-in requires at least 12 characters, mixed character
classes, and screens passwords against HaveIBeenPwned.
"""
import json
from datetime import datetime


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


def as_list(value):
    """Fan-out steps return a list of per-project responses; single calls return one object."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def unwrap_item(item, *keys):
    """Per-project responses may still carry an apiResponse/data envelope."""
    for _ in range(3):
        if not isinstance(item, dict):
            return {}
        for k in ("apiResponse", "response", "result", "data"):
            inner = item.get(k)
            if isinstance(inner, dict):
                item = inner
                break
        else:
            break
    for k in keys:
        if isinstance(item, dict) and k in item:
            return item
    return item if isinstance(item, dict) else {}


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)
def pick_list(data, key):
    """The fan-out step may deliver its list at `key`, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data)
    return []


def auth_configs(data):
    """Return (ref, authConfig) pairs from the fanned-out auth config responses."""
    items = as_list(pick_list(data, "authConfig"))
    out = []
    for idx, raw in enumerate(items):
        item = unwrap_item(raw, "password_min_length", "saml_enabled", "mfa_totp_verify_enabled")
        ref = item.get("ref") or item.get("projectRef") or "project[%d]" % idx
        out.append((ref, item if isinstance(item, dict) else {}))
    return out


MIN_LENGTH = 12


def evaluate(data):
    configs = auth_configs(data)
    compliant, weak, unreadable, not_applicable = [], [], [], []
    findings = []
    for ref, cfg in configs:
        if not cfg:
            unreadable.append(ref)
            continue
        if cfg.get("external_email_enabled") is False and cfg.get("external_phone_enabled") is False:
            not_applicable.append(ref)
            continue
        length = cfg.get("password_min_length")
        hibp = bool(cfg.get("password_hibp_enabled"))
        classes = str(cfg.get("password_required_characters") or "")
        if length is None:
            unreadable.append(ref)
            continue
        gaps = []
        if length < MIN_LENGTH:
            gaps.append("minimum length %s" % length)
        if not classes:
            gaps.append("no required character classes")
        if not hibp:
            gaps.append("breached-password screening off")
        if gaps:
            weak.append(ref)
            findings.append({"project": ref, "gaps": gaps})
        else:
            compliant.append(ref)
    measured = len(compliant) + len(weak)
    result = {
        "isStrongPasswordPolicyEnforced": measured > 0 and not weak,
        "passwordPolicyCoveragePercentage": pct(len(compliant), measured),
        "projectsEvaluated": measured,
        "projectsWithWeakPolicy": weak[:25],
        "projectsNotMeasured": unreadable,
        "projectsWithoutPasswordAuth": not_applicable,
        "minimumLengthRequired": MIN_LENGTH,
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append(
            "No project returned a readable auth configuration with a password policy, so "
            "password strength could not be measured."
        )
    elif not weak:
        passes.append(
            "All %d measured project(s) require at least %d characters, mixed character "
            "classes, and screen passwords against known breaches."
            % (measured, MIN_LENGTH)
        )
    else:
        fails.append(
            "%d of %d measured project(s) fall short of the password baseline: %s."
            % (len(weak), measured, ", ".join(weak[:10]))
        )
        recs.append(
            "Under Authentication > Policies set the minimum password length to %d or more, "
            "require lower, upper, digit and symbol classes, and enable leaked password "
            "protection." % MIN_LENGTH
        )
    return result, passes, fails, recs, {"projectsEvaluated": measured},


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
            "transformationId": "isStrongPasswordPolicyEnforced",
            "vendor": "Supabase",
            "category": "Data Security",
        },
    )
