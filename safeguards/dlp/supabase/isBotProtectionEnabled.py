"""
Transformation: isBotProtectionEnabled
Vendor: Supabase  |  Category: Data Security
Source: GET /v1/projects/{ref}/config/auth, fanned out across projects
Pass: every project with open sign-up runs CAPTCHA protection on auth endpoints.
Projects with sign-up disabled are counted as not applicable rather than passing.
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


def _as_list(value):
    """Fan-out steps return a list of per-project responses; single calls return one object."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _unwrap(item, *keys):
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


def _pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)
def _pick(data, key):
    """The fan-out step may deliver its list at `key`, or as the whole payload."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data)
    return []


def _auth_configs(data):
    """Return (ref, authConfig) pairs from the fanned-out auth config responses."""
    items = _as_list(_pick(data, "authConfig"))
    out = []
    for idx, raw in enumerate(items):
        item = _unwrap(raw, "password_min_length", "saml_enabled", "mfa_totp_verify_enabled")
        ref = item.get("ref") or item.get("projectRef") or "project[%d]" % idx
        out.append((ref, item if isinstance(item, dict) else {}))
    return out


def evaluate(data):
    configs = _auth_configs(data)
    protected, unprotected, closed_signup, unreadable = [], [], [], []
    providers = {}
    for ref, cfg in configs:
        if not cfg or "security_captcha_enabled" not in cfg:
            unreadable.append(ref)
            continue
        if cfg.get("disable_signup"):
            closed_signup.append(ref)
            continue
        if cfg.get("security_captcha_enabled"):
            protected.append(ref)
            providers[ref] = cfg.get("security_captcha_provider")
        else:
            unprotected.append(ref)
    measured = len(protected) + len(unprotected)
    result = {
        "isBotProtectionEnabled": measured > 0 and not unprotected,
        "botProtectionCoveragePercentage": _pct(len(protected), measured),
        "projectsEvaluated": measured,
        "projectsWithoutCaptcha": unprotected[:25],
        "projectsWithSignupDisabled": closed_signup,
        "projectsNotMeasured": unreadable,
        "captchaProviders": providers,
    }
    passes, fails, recs = [], [], []
    if measured == 0 and closed_signup:
        passes.append(
            "Every readable project has public sign-up disabled, so there is no open "
            "registration surface to protect."
        )
        result["isBotProtectionEnabled"] = True
    elif measured == 0:
        fails.append("No project reported CAPTCHA settings.")
    elif not unprotected:
        passes.append(
            "All %d project(s) with open sign-up run CAPTCHA protection on auth endpoints."
            % measured
        )
    else:
        fails.append(
            "%d of %d project(s) with open sign-up run no CAPTCHA, leaving registration and "
            "password reset open to automated abuse: %s."
            % (len(unprotected), measured, ", ".join(unprotected[:10]))
        )
        recs.append(
            "Enable CAPTCHA protection under Authentication > Attack Protection, or disable "
            "public sign-up, for each project listed."
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
            "transformationId": "isBotProtectionEnabled",
            "vendor": "Supabase",
            "category": "Data Security",
        },
    )
