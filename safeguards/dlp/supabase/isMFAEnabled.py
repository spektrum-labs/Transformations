"""
Transformation: isMFAEnabled
Vendor: Supabase  |  Category: Data Security
Source: GET /v1/projects/{ref}/config/auth, fanned out across projects
Pass: every project offers at least one second factor for verification - TOTP, WebAuthn
or passkey. Measures the project's own end-user authentication, not Supabase console
administrator MFA, which the Management API does not expose.
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
    with_mfa, without_mfa, unreadable = [], [], []
    factor_rows = []
    for ref, cfg in configs:
        if not cfg:
            unreadable.append(ref)
            continue
        factors = []
        if cfg.get("mfa_totp_verify_enabled"):
            factors.append("totp")
        if cfg.get("mfa_web_authn_verify_enabled"):
            factors.append("webauthn")
        if cfg.get("passkey_enabled"):
            factors.append("passkey")
        if cfg.get("mfa_phone_verify_enabled"):
            factors.append("phone")
        if "mfa_totp_verify_enabled" not in cfg and "passkey_enabled" not in cfg:
            unreadable.append(ref)
            continue
        factor_rows.append({"project": ref, "factors": factors})
        (with_mfa if factors else without_mfa).append(ref)
    measured = len(with_mfa) + len(without_mfa)
    result = {
        "isMFAEnabled": measured > 0 and not without_mfa,
        "mfaCoveragePercentage": _pct(len(with_mfa), measured),
        "projectsEvaluated": measured,
        "projectsWithoutMfa": without_mfa[:25],
        "projectsNotMeasured": unreadable,
        "phoneOnlyProjectCount": len([r for r in factor_rows if r["factors"] == ["phone"]]),
    }
    passes, fails, recs = [], [], []
    if measured == 0:
        fails.append("No project returned a readable MFA configuration.")
    elif not without_mfa:
        passes.append(
            "All %d measured project(s) offer at least one second factor for end-user "
            "verification." % measured
        )
    else:
        fails.append(
            "%d of %d measured project(s) verify no second factor: %s."
            % (len(without_mfa), measured, ", ".join(without_mfa[:10]))
        )
        recs.append(
            "Enable TOTP or WebAuthn verification under Authentication > Multi-Factor for "
            "each project listed."
        )
    if result["phoneOnlyProjectCount"]:
        recs.append(
            "%d project(s) rely on SMS as the only second factor. SMS is the weakest "
            "supported factor; add TOTP or WebAuthn." % result["phoneOnlyProjectCount"]
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
            "transformationId": "isMFAEnabled",
            "vendor": "Supabase",
            "category": "Data Security",
        },
    )
