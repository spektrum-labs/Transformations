"""
Transformation: isSCIMProvisioningEnabled
Vendor: OpenAI  |  Category: Artificial Intelligence
Product: OpenAI API (API Platform)
Evaluates: SCIM provisioning is in use: at least one human organization member is SCIM-managed (is_scim_managed).
API Source: listOrganizationUsers (GET /v1/organization/users, all pages)
Credential: Admin API key (sk-admin-...). Endpoints confirmed in the OpenAI OpenAPI spec
(github.com/openai/openai-openapi, security AdminApiKeyAuth).
Fails closed: a refused call, an unrecognised body or a partial read is False with the reason.
"""
import json
from datetime import datetime, timezone

KEY = "isSCIMProvisioningEnabled"


def extract_input(raw):
    """Return (data, validation) from the enriched, wrapped, string or bare input.

    Token-Service hands this file the enriched form {"data": <raw response>, "validation": ...}
    because the evaluate() below reads input.get("data"). That keeps the OpenAI list
    envelope (has_more) and the workflow siblings (projectApiKeys, orgDataRetention) intact;
    the legacy drill into "data" would drop both. A string that is not JSON raises into
    transform()'s handler: fail closed.
    """
    if isinstance(raw, (str, bytes)):
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        raw = json.loads(raw)
    if isinstance(raw, dict) and "data" in raw and "validation" in raw:
        return raw["data"], raw["validation"]
    data = raw
    if isinstance(data, dict):
        for attempt in range(3):
            unwrapped = False
            for key in ("api_response", "response", "result", "apiResponse", "Output"):
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    errors = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if errors else "success",
                "errors": errors,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "OpenAI",
                "category": "Artificial Intelligence",
            },
        },
    }


# A refused call is not a posture finding: the control's state is unknown, so the key is
# false with the reason, never true. OpenAI documents: "Admin API keys cannot be used for
# non-administration endpoints"; the reverse holds too - a project key gets 401/403 here.
REFUSAL_REASONS = {
    401: "the key was rejected. The /v1/organization/* endpoints accept only an Admin API key "
         "(sk-admin-...) created by an organization owner at platform.openai.com/settings/organization/admin-keys.",
    403: "the key is not permitted to call this Administration API endpoint. Use an Admin API key "
         "(sk-admin-...); a project key (sk-proj-...) cannot read organization settings.",
    404: "OpenAI reported the resource as not found. The setting may not be configured for this organization.",
    429: "OpenAI rate-limited the call. Retry on the next evaluation.",
}


def detect_refusal(data):
    """Return a reason string when the payload is an error envelope, else None."""
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if not (err or data.get("errorType") or data.get("status") == "Error"):
        return None
    status = data.get("statusCode") or data.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    why = REFUSAL_REASONS.get(status, "the vendor call did not succeed.")
    detail = data.get("message") or data.get("errorMessage") or ""
    if isinstance(err, dict) and err.get("message"):
        detail = err.get("message")
    if detail:
        why = why + " Vendor said: " + str(detail)
    if status:
        why = "HTTP " + str(status) + ": " + why
    return why


def read_list(obj):
    """(items, complete) for an OpenAI list envelope {object, data, has_more}.

    complete is True only when has_more is literally False: every page was read. A bare list,
    a missing has_more, or has_more true (the pager stopped early) is incomplete.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("data"), list):
        return None, False
    return [i for i in obj["data"] if isinstance(i, dict)], obj.get("has_more") is False


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(float(value.strip()))
        except ValueError:
            return None
    return None


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def fail(validation, reason, recommendation=None, summary=None, extra=None):
    result = {KEY: False}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, fail_reasons=[reason],
                           recommendations=[recommendation] if recommendation else [],
                           input_summary=summary or {})


def refused_or_unrecognised(data, validation, what):
    why = detect_refusal(data)
    if why:
        return fail(validation, "The OpenAI call did not return data - " + why +
                    " This is a credential or reachability result, not a finding; the control's state is unknown.",
                    "Reconnect the OpenAI integration with an Admin API key.", {"endpointReachable": False})
    return fail(validation, what + " response not recognised - no OpenAI list or object in the payload.",
                "Inspect the raw integration response.", {"endpointReachable": None})


def transform(input):
    try:
        if isinstance(input, dict) and "validation" in input:
            return evaluate({"data": input.get("data"), "validation": input.get("validation")})
        return evaluate(input)
    except Exception as exc:
        return create_response(
            result={KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
        )

def evaluate(input):
    data, validation = extract_input(input)
    items, complete = read_list(data)
    if items is None:
        return refused_or_unrecognised(data, validation, "Organization users")
    humans = [u for u in items if u.get("is_service_account") is not True]
    reported = [u for u in humans if isinstance(u.get("is_scim_managed"), bool)]
    scim = [u for u in reported if u.get("is_scim_managed") is True]
    summary = {"humans": len(humans), "scimManaged": len(scim), "complete": complete}
    if not humans:
        return fail(validation, "No human organization members were returned.", None, summary)
    if not reported:
        return fail(validation, "OpenAI did not report is_scim_managed for any member, so SCIM use cannot be shown.",
                    None, summary)
    if not scim:
        return fail(validation, "None of the " + str(len(reported)) + " human members is SCIM-managed: membership is not "
                    "provisioned from an identity provider.",
                    "Configure SCIM provisioning from the identity provider (Organization settings > Security).", summary,
                    {"scimManaged": 0, "humans": len(humans)})
    others = len(reported) - len(scim)
    findings = []
    if others:
        findings = [str(others) + " human member(s) are not SCIM-managed (for example the organization creator); "
                    "SCIM is in use but does not cover everyone."]
    return create_response(result={KEY: True, "scimManaged": len(scim), "humans": len(humans)},
                           validation=validation,
                           pass_reasons=[str(len(scim)) + " of " + str(len(reported)) + " human members are provisioned "
                                         "through SCIM, so SCIM provisioning is enabled for the organization."],
                           additional_findings=findings, input_summary=summary)
