"""
Transformation: isSCIMProvisioningEnabled
Vendor: OpenAI  |  Category: Artificial Intelligence
Product: OpenAI API (API Platform)
Evaluates: SCIM provisioning is in use, read from whichever object OpenAI reports it on.
API Source: listOrganizationGroups (GET /v1/organization/groups, all pages) preferred;
listOrganizationUsers (GET /v1/organization/users, all pages) accepted.
Credential: Admin API key (sk-admin-...). Endpoints confirmed in the OpenAI OpenAPI spec
(github.com/openai/openai-openapi, security AdminApiKeyAuth).
Fails closed: a refused call, an unrecognised body or a partial read is None with the reason,
so the criterion is recorded as not evaluated rather than failed.

WHICH OBJECT CARRIES SCIM STATE, AND WHY THIS FILE READS BOTH
OpenAI's spec (openapi.yaml 2.3.0) defines the fact on two objects with different guarantees:

  GroupResponse.is_scim_managed  -- the object GET /v1/organization/groups returns. Listed
      under `required`, so EVERY group object carries it. "Whether the group is managed
      through SCIM and controlled by your identity provider."
  User.is_scim_managed           -- present on the User schema, but NOT under `required`, and
      absent from OpenAI's own published example for both the user object and the user list.

This file used to read the user field alone and report False when no user carried it. That is
an absence of evidence, not evidence of absence: Spektrum Labs' own live /v1/organization/users
body carries the field on no user at all, so the criterion returned a permanent measured red
that no amount of SCIM configuration could clear. A user list that does not report the field is
now not measured, and groups -- where the field is guaranteed -- are the preferred source.

Reading both shapes is deliberate. The definition has no groups method yet, so the transform
has to keep working on the user list it is handed today and start measuring properly the moment
the method is added, without a window where the two are out of step (sequencing rule 2).

HONEST LIMIT. A SCIM-managed group proves the group's membership is driven by the identity
provider. It does not prove every member of the organization is provisioned that way, which is
what the key's name suggests. The pass reason says which was measured.
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
                    additional_findings=None, api_errors=None):
    """Build the 5-section response, deriving "was this measured?" from the criterion's value.

    dataCollection.status used to be the literal "success" here, which is the only thing
    Token-Service reads when it decides whether a criterion was evaluated. A refused call, an
    unreadable body or a crash therefore reached the customer as a measured FAILED and wrote a
    real gap. The status is now derived from api_errors, and api_errors is derived from the
    value under KEY -- so the branch that could not measure does not have to remember to say
    so, which is the branch that gets this wrong every time.
    """
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if not api_errors and isinstance(result, dict) and result.get(KEY) is None:
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    api_err_list = api_errors or []
    errors = transformation_errors or []
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


def respond(value, validation, reason, recommendation=None, summary=None, extra=None):
    """One exit for both answers. value is False for a measured failure, None for no evidence.

    Keeping them in one function is deliberate: the caller chooses a value, not a status, and
    create_response derives the status from the value. There is no way to set one and forget
    the other.
    """
    result = {KEY: value}
    if extra:
        result.update(extra)
    return create_response(result=result, validation=validation, fail_reasons=[reason],
                           recommendations=[recommendation] if recommendation else [],
                           input_summary=summary or {})


def fail(validation, reason, recommendation=None, summary=None, extra=None):
    """The control was measured and it is not in place."""
    return respond(False, validation, reason, recommendation, summary, extra)


def not_measured(validation, reason, recommendation=None, summary=None, extra=None):
    """Nothing was measured: a refusal, an unreadable body, a partial read, a crash.

    Returns None rather than False so the criterion fails closed under every comparator --
    greaterThan and lessThan coerce False to 0 and pass -- and so create_response sets
    dataCollection.status to "error", which is what Token-Service reads to record the
    criterion as not evaluated instead of writing a gap.
    """
    return respond(None, validation, reason, recommendation, summary, extra)


def refused_or_unrecognised(data, validation, what):
    why = detect_refusal(data)
    if why:
        return not_measured(validation, "The OpenAI call did not return data - " + why +
                            " This is a credential or reachability result, not a finding; the control's state is unknown.",
                            "Reconnect the OpenAI integration with an Admin API key.", {"endpointReachable": False})
    return not_measured(validation, what + " response not recognised - no OpenAI list or object in the payload.",
                        "Inspect the raw integration response.", {"endpointReachable": None})


def transform(input):
    try:
        if isinstance(input, dict) and "validation" in input:
            return evaluate({"data": input.get("data"), "validation": input.get("validation")})
        return evaluate(input)
    except Exception as exc:
        # None, not False: a crash measured nothing. create_response reads the value and sets
        # dataCollection.status to "error", the only channel evaluate.py consults. The
        # transformation channel this used to report down is read by vacuous_output.py, which
        # is not on the grading path at all.
        return create_response(
            result={KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
        )

def is_group(item):
    """A group object, told apart from a user object by what OpenAI puts on each.

    GET /v1/organization/groups returns GroupResponse, whose required fields include
    group_type and is_scim_managed; GET /v1/organization/users returns User, whose object
    field is the constant "organization.user". Shape, not endpoint: the definition names the
    method, but the transform is handed whatever that method returned.
    """
    if item.get("object") == "organization.user":
        return False
    return item.get("object") == "group" or "group_type" in item or "scim_managed" in item


def scim_flag(item):
    """The SCIM boolean, or None when this object does not report one.

    The vendor spells the same fact two ways: is_scim_managed on GroupResponse (the list
    endpoint) and on User, scim_managed on the Group summary embedded in role assignments.
    Reading only one of them is how this check came to read a field its endpoint never sent,
    so read both and treat anything that is not a boolean as not reported.
    """
    for name in ("is_scim_managed", "scim_managed"):
        value = item.get(name)
        if isinstance(value, bool):
            return value
    return None


def evaluate(input):
    data, validation = extract_input(input)
    items, complete = read_list(data)
    if items is None:
        return refused_or_unrecognised(data, validation, "Organization groups or users")

    groups = [g for g in items if is_group(g)]
    if groups:
        reported = [g for g in groups if scim_flag(g) is not None]
        scim = [g for g in reported if scim_flag(g)]
        summary = {"groups": len(groups), "scimManagedGroups": len(scim), "complete": complete}
        if not reported:
            return not_measured(validation, "OpenAI returned " + str(len(groups)) + " group(s) but reported "
                                "is_scim_managed on none of them, so SCIM provisioning cannot be read.",
                                "Inspect the raw listOrganizationGroups response.", summary)
        if scim:
            others = len(reported) - len(scim)
            findings = []
            if others:
                findings = [str(others) + " group(s) are not SCIM-managed, so some membership is still "
                            "maintained in OpenAI rather than in the identity provider."]
            return create_response(result={KEY: True, "scimManagedGroups": len(scim), "groups": len(groups)},
                                   validation=validation,
                                   pass_reasons=[str(len(scim)) + " of " + str(len(reported)) + " organization groups are "
                                                 "managed through SCIM and controlled by the identity provider. This "
                                                 "proves group membership is provisioned from the IdP; it does not prove "
                                                 "every individual member is."],
                                   additional_findings=findings, input_summary=summary)
        # No SCIM-managed group. That is only a finding if the whole list was read: "none of
        # the groups on page one" is a sample, not an estate.
        if not complete:
            return not_measured(validation, "No SCIM-managed group was found, but the group list was not read to the end "
                                "(has_more is not false), so the groups that were not read may be SCIM-managed.",
                                "Check the listOrganizationGroups pagination settings.", summary)
        return fail(validation, "None of the " + str(len(reported)) + " organization groups is managed through SCIM, so "
                    "group membership is maintained in OpenAI rather than provisioned from an identity provider.",
                    "Connect the identity provider and enable SCIM provisioning (Organization settings > Security).",
                    summary, {"scimManagedGroups": 0, "groups": len(groups)})

    # A user list. User.is_scim_managed is in OpenAI's schema but not in its `required` set,
    # and OpenAI's own published example omits it, so its absence says nothing about SCIM.
    humans = [u for u in items if u.get("is_service_account") is not True]
    reported = [u for u in humans if isinstance(u.get("is_scim_managed"), bool)]
    scim = [u for u in reported if u.get("is_scim_managed") is True]
    summary = {"humans": len(humans), "scimManaged": len(scim), "complete": complete}
    if not humans:
        return not_measured(validation, "No human organization members were returned.", None, summary)
    if not reported:
        return not_measured(validation, "OpenAI did not report is_scim_managed on any of the " + str(len(humans)) +
                            " member(s) returned. The field is optional on the user object, so its absence is not "
                            "evidence that SCIM is unused; SCIM state is reported unconditionally on groups.",
                            "Wire this criterion to GET /v1/organization/groups, which reports is_scim_managed on "
                            "every group.", summary)
    # Same rule as the group path above: "none of the members on the pages we read" is a
    # sample, not an estate. Finding one SCIM-managed member settles the True whatever went
    # unread, which is why the check above this one needs no completeness test; finding none
    # settles nothing, because the members not read may be exactly the SCIM-managed ones.
    if not scim and not complete:
        return not_measured(validation, "No SCIM-managed member was found, but the user list was not read to the end "
                            "(has_more is not false), so members that were not read may be SCIM-managed.",
                            "Check the listOrganizationUsers pagination settings.", summary)
    if not scim:
        return fail(validation, "None of the " + str(len(reported)) + " human members that reported is_scim_managed is "
                    "SCIM-managed: membership is not provisioned from an identity provider.",
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
