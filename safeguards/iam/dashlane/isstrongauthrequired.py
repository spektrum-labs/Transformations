"""Transformation: isStrongAuthRequired - Dashlane (password manager), Public API POST /public/teams/Members.

True only on a complete read of the team's members where at least one member is active (status accepted) and every active
member signs in with a second factor or an identity provider: authentication.type is sso, totp_device_registration or
totp_login. A member whose type is email_token (a code sent by email) or who reports no authentication is not covered, so
the answer is False. An error body, an empty list, no active member or a partial read is not measured (None).
"""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]
VENDOR = "Dashlane"


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error, truncated) for the first dict, through any wrapper, that carries key `wanted`.

    `truncated` is True when Integration-Service marked the read partial (paginationTruncated / truncated) on any
    wrapper level it passed through.
    """
    cur = obj
    truncated = False
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, truncated
        if not isinstance(cur, dict):
            return None, None, truncated
        if cur.get("paginationTruncated") is True or cur.get("truncated") is True:
            truncated = True
        if wanted in cur:
            return cur, None, truncated
        problem = error_in(cur)
        if problem is not None:
            return None, problem, truncated
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None, truncated
        cur = nxt
    return None, None, truncated


def raw_body(input):
    # A {data, validation} envelope means Token-Service passed the undrilled response.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "iam"},
    )


STRONG_AUTH = ("sso", "totp_device_registration", "totp_login")
ACTIVE_STATUS = "accepted"


def read_members(input):
    """(members, None) for a complete Dashlane member list, else (None, problem)."""
    box, problem, truncated = find_key(raw_body(input), "members")
    if problem is not None:
        return None, "Dashlane returned an error instead of the member list: " + problem
    if box is None or not isinstance(box.get("members"), list):
        return None, "No Dashlane member list in the response; nothing to evaluate."
    members = box["members"]
    records = [m for m in members if isinstance(m, dict)]
    if len(records) != len(members):
        return None, "The member list holds entries that are not member records, so it cannot be scored."
    if truncated:
        return None, "Read stopped at the page limit (" + str(len(records)) + " members); a partial read is not scored."
    return records, None


def active_members(members):
    return [m for m in members if str(m.get("status") or "").lower() == ACTIVE_STATUS]


def has_strong_auth(member):
    auth = member.get("authentication")
    if not isinstance(auth, dict):
        return False
    return str(auth.get("type") or "").lower() in STRONG_AUTH


def role_flag(member, name):
    role = member.get("role")
    return isinstance(role, dict) and role.get(name) is True


def transform(input):
    key = "isStrongAuthRequired"
    validation = extract_validation(input)
    members, problem = read_members(input)
    if problem is not None:
        return not_measured(key, problem, validation)
    active = active_members(members)
    if not active:
        return not_measured(key, "Dashlane lists no active member (status accepted), so there is no one to judge.", validation)
    covered = [m for m in active if has_strong_auth(m)]
    uncovered = len(active) - len(covered)
    ok = uncovered == 0
    text = (str(len(covered)) + " of " + str(len(active)) + " active Dashlane members sign in with SSO or two-factor authentication.")
    return create_response(
        result={key: ok, "activeMembers": len(active), "strongAuthMembers": len(covered), "membersWithoutStrongAuth": uncovered},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text + " " + str(uncovered) + " rely on the master password and an emailed code only."],
        recommendations=[] if ok else ["Require two-factor authentication or SSO for every Dashlane member in the Admin Console."],
        input_summary={"activeMembers": len(active), "strongAuthMembers": len(covered)},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "iam"},
    )
