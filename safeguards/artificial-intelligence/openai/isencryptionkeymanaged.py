"""
Transformation: isEncryptionKeyManaged
Vendor: OpenAI  |  Category: Artificial Intelligence
Product: OpenAI API (API Platform)
Evaluates: Every active project encrypts its data with a customer-managed key (Project.external_key_id
is set), rather than only OpenAI-managed encryption.
API Source: listProjects (GET /v1/organization/projects, all pages, active projects only)
Credential: Admin API key (sk-admin-...). Endpoint and the external_key_id field confirmed in the
OpenAI OpenAPI spec (github.com/openai/openai-openapi: Project.external_key_id).
True only from a complete read in which every active project names an external key. A project
whose external_key_id is null or empty is False. A refused call, an unrecognised body, a partial
read, no active project, a project with no external_key_id field and an exception inside this file
answer None with dataCollection.status "error", which Token-Service records as not evaluated.
"""
import json
from datetime import datetime, timezone

KEY = "isEncryptionKeyManaged"


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
                    additional_findings=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    errors = transformation_errors or []
    api_err_list = api_errors or []
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
# None (not evaluated) with the reason, never true and never false. OpenAI documents:
# "Admin API keys cannot be used for non-administration endpoints"; the reverse holds
# too - a project key gets 401/403 here.
REFUSAL_REASONS = {
    401: "the key was rejected. The /v1/organization/* endpoints accept only an Admin API key "
         "(sk-admin-...) created by an organization owner at platform.openai.com/settings/organization/admin-keys.",
    403: "the key is not permitted to call this Administration API endpoint. Use an Admin API key "
         "(sk-admin-...); a project key (sk-proj-...) cannot read organization settings.",
    404: "OpenAI reported the resource as not found. The setting may not be configured for this organization.",
    429: "OpenAI rate-limited the call. Retry on the next evaluation.",
}


def detect_refusal(data):
    """Return (status, reason) when the payload is an error envelope, else None.

    The reason is fixed text. The vendor's own message is never copied in: OpenAI's
    invalid-key message echoes part of the key it was given.
    """
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
    if status:
        why = "HTTP " + str(status) + ": " + why
    return status, why


def read_list(obj):
    """(items, complete) for an OpenAI list envelope {object, data, has_more}.

    complete is True only when has_more is literally False: every page was read. A bare list,
    a missing has_more, or has_more true (the pager stopped early) is incomplete.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("data"), list):
        return None, False
    return [i for i in obj["data"] if isinstance(i, dict)], obj.get("has_more") is False


def not_measured(validation, reason, recommendation=None, extra=None, summary=None,
                 transformation_errors=None):
    """No verdict: the key is None and dataCollection.status is "error", so the evaluator
    shows Not evaluated instead of a failed check. extra carries facts really read (an
    event count of zero, the HTTP status) next to the missing verdict."""
    result = {KEY: None}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, fail_reasons=[reason],
                           recommendations=[recommendation] if recommendation else [],
                           input_summary=summary or {}, api_errors=[reason],
                           transformation_errors=transformation_errors)


def refused_or_unrecognised(data, validation, what):
    refusal = detect_refusal(data)
    if refusal:
        status, why = refusal
        return not_measured(validation, "The OpenAI call did not return data - " + why +
                            " This is a credential or reachability result, not a finding; the control's state is unknown.",
                            "Reconnect the OpenAI integration with an Admin API key.",
                            {"endpointReachable": False, "httpStatus": status})
    return not_measured(validation, what + " response not recognised - no OpenAI list or object in the payload.",
                        "Inspect the raw integration response.", {"endpointReachable": None})




def active_projects(data, validation):
    """(active projects, None) from a complete project list, or (None, a Not evaluated response)."""
    projects, complete = read_list(data)
    if projects is None:
        return None, refused_or_unrecognised(data, validation, "Project list")
    if not complete:
        return None, not_measured(validation,
                                  "The project list was not fully read (has_more is not false), so a project "
                                  "outside the read could answer differently. The control was not evaluated.",
                                  "Re-run the evaluation; if it repeats, inspect the integration's paging.",
                                  {"projectsRead": len(projects)})
    active = []
    for p in projects:
        if p.get("archived_at") is not None or str(p.get("status") or "active").lower() == "archived":
            continue
        active.append(p)
    if not active:
        return None, not_measured(validation,
                                  "GET /v1/organization/projects returned no active project, so there is "
                                  "nothing to evaluate.",
                                  "Re-run once the organization has an active project.",
                                  {"activeProjects": 0})
    return active, None


def project_name(p):
    return str(p.get("name") or p.get("id"))


def transform(input):
    try:
        if isinstance(input, dict) and "validation" in input:
            return evaluate({"data": input.get("data"), "validation": input.get("validation")})
        return evaluate(input)
    except Exception as exc:
        return not_measured(
            {"status": "error", "errors": [], "warnings": []},
            "The project list could not be read, so the control's state is unknown.",
            "Report this to the Spektrum integrations team with the raw API response.",
            transformation_errors=[str(exc)],
        )


def evaluate(input):
    data, validation = extract_input(input)
    active, early = active_projects(data, validation)
    if early:
        return early
    unmanaged = []
    unknown = []
    for p in active:
        if "external_key_id" not in p:
            unknown.append(project_name(p))
            continue
        key_id = p.get("external_key_id")
        if key_id is None or (isinstance(key_id, str) and not key_id.strip()):
            unmanaged.append(project_name(p))
        elif not isinstance(key_id, str):
            unknown.append(project_name(p))
    summary = {"activeProjects": len(active), "unmanagedProjects": len(unmanaged), "unreadProjects": len(unknown)}
    if unmanaged:
        return create_response(
            result={KEY: False, "activeProjects": len(active), "unmanagedProjects": len(unmanaged)},
            validation=validation,
            fail_reasons=[str(len(unmanaged)) + " of " + str(len(active)) + " active project(s) have no customer-managed "
                          "encryption key: " + ", ".join(unmanaged[:10]) + "."],
            recommendations=["Set up OpenAI Enterprise Key Management (EKM) with a key from your cloud KMS and "
                             "assign it to each project."],
            input_summary=summary,
        )
    if unknown:
        return not_measured(validation,
                            str(len(unknown)) + " active project(s) came back without a readable external_key_id, so "
                            "their key could not be read: " + ", ".join(unknown[:10]) + ". The control was not evaluated.",
                            "Inspect the raw integration response.",
                            {"activeProjects": len(active)}, summary)
    return create_response(
        result={KEY: True, "activeProjects": len(active)},
        validation=validation,
        pass_reasons=["All " + str(len(active)) + " active project(s) name a customer-managed encryption key "
                      "(external_key_id is set)."],
        input_summary=summary,
    )
