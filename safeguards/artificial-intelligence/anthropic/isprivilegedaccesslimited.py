"""
Transformation: isPrivilegedAccessLimited
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude Developer Platform (Claude API)
Evaluates: Ensures privileged organization roles are held by a limited subset of members rather than distributed broadly.
API Source: listOrganizationUsers
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
        for attempt in range(3):
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
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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


METADATA = {
    "transformationId": "isPrivilegedAccessLimited",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


# Unique sentinel. object() is unavailable in the RestrictedPython sandbox
# Token-Service runs transforms in, so a fresh list is used instead: a list
# literal is never interned, which keeps the "is MISSING" identity checks valid.
MISSING = ["__missing__"]

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN
# rather than absent. Anthropic's compliance org-data endpoints (settings, groups,
# organizations, users) accept only a Compliance Access Key (sk-ant-api01-...)
# created in claude.ai; an Admin API key (sk-ant-admin01-...) gets 403, and a
# standalone Claude Console organization can reach the Activity Feed only.
REFUSAL_REASONS = {
    401: ("the credential was rejected",
          "Confirm the key is an admin-class key and has not been revoked or expired."),
    403: ("this organization's credential is not permitted to call the endpoint",
          "This endpoint requires a Compliance Access Key (sk-ant-api01-...) created in "
          "claude.ai > Organization settings > API with the read:org_audit scope. An Admin "
          "API key (sk-ant-admin01-...) from Claude Console returns 403 here. A standalone "
          "Claude Console organization cannot read these settings at all - treat this "
          "criterion as not applicable for that tenant rather than failed."),
    404: ("the endpoint or organization was not found",
          "Check the Organization ID. The compliance endpoints take a compliance "
          "organization uuid from GET /v1/compliance/organizations, which is a different "
          "value from the Console organization id shown at "
          "platform.claude.com/settings/organization."),
    429: ("the vendor rate-limited the call",
          "Compliance endpoints allow 600 requests/minute per parent organization. Retry."),
}


def detect_refusal(data):
    """Return (status, why, fix) when the payload is an error envelope, else None."""
    if not isinstance(data, dict):
        return None
    if not (data.get("error") or data.get("errorType") or data.get("status") == "Error"):
        return None
    status = data.get("statusCode") or data.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    why, fix = REFUSAL_REASONS.get(status, (
        "the vendor call did not succeed",
        "Inspect the integration method response for the underlying error."))
    detail = data.get("message") or data.get("errorMessage") or ""
    if detail:
        why = why + " (" + str(detail) + ")"
    return status, why, fix


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "enabled", "on")
    return bool(value)


def settings_map(data):
    """Reduce the effective-settings rows to {name: value}.

    A setting this organization's administrators cannot change is omitted from
    the response entirely, so a missing name means "not controllable here",
    never "off". Callers must distinguish absent from False, which is why this
    returns a plain dict and callers use the _MISSING sentinel.
    """
    rows = None
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("data", "settings"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
    if rows is None:
        rows = []
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name") is not None:
            out[row["name"]] = row.get("value", MISSING)
    return out


PRIVILEGED_ROLES = ("admin", "owner", "primary_owner", "membership_admin")
MAX_PRIVILEGED_RATIO = 0.25
SMALL_ORG_ALLOWANCE = 2  # two privileged members is a continuity floor, never a finding


def evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    refusal = detect_refusal(data)
    if refusal:
        refusal_status, refusal_why, refusal_fix = refusal
        return create_response(
            result={"isPrivilegedAccessLimited": False, "endpointReachable": False, "httpStatus": refusal_status},
            validation=validation,
            fail_reasons=[
                "The vendor call did not return data because " + refusal_why +
                ". This is a connectivity or credential-scope result, not a finding about "
                "the organization's configuration - the control's real state is unknown."
            ],
            recommendations=[refusal_fix],
            input_summary={"endpointReachable": False, "httpStatus": refusal_status},
            metadata=METADATA,
        )

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data")
        if not isinstance(items, list):
            items = data.get("users")
    else:
        items = None
    if not isinstance(items, list):
        items = []

    total = len(items)
    if total == 0:
        return create_response(
            result={"isPrivilegedAccessLimited": False, "totalMembers": 0, "privilegedMembers": 0},
            validation=validation,
            fail_reasons=["GET /v1/organizations/users returned no members, so privileged access could not be assessed."],
            recommendations=["Confirm the key carries the read:members or read:org_audit scope."],
            input_summary={"totalMembers": 0},
            metadata=METADATA,
        )

    privileged = [u for u in items
                  if isinstance(u, dict) and str(u.get("role", "")).lower() in PRIVILEGED_ROLES]
    count = len(privileged)
    ratio = count / float(total)
    pct = round(ratio * 100, 2)

    if count == 0:
        return create_response(
            result={"isPrivilegedAccessLimited": False, "totalMembers": total, "privilegedMembers": 0,
                    "privilegedRatio": 0.0},
            validation=validation,
            fail_reasons=[
                "No member of the " + str(total) + " returned holds a privileged role. Every "
                "organization has at least a primary owner, so this indicates a truncated roster "
                "or an unreadable role field rather than well-governed access."
            ],
            recommendations=[
                "Confirm the member list was paginated to exhaustion and that the role field is populated."
            ],
            input_summary={"totalMembers": total, "privilegedMembers": 0},
            metadata=METADATA,
        )

    result = count <= SMALL_ORG_ALLOWANCE or ratio <= MAX_PRIVILEGED_RATIO
    roles_seen = sorted({str(u.get("role", "")).lower() for u in privileged})

    if result and count <= SMALL_ORG_ALLOWANCE and ratio > MAX_PRIVILEGED_RATIO:
        pass_reasons = [
            str(count) + " of " + str(total) + " members hold a privileged role (" + str(pct) +
            "%), which is above the " + str(round(MAX_PRIVILEGED_RATIO * 100, 2)) + "% threshold "
            "but within the two-member continuity floor for small organizations."
        ]
        fail_reasons = []
        recommendations = []
    elif result:
        pass_reasons = [
            str(count) + " of " + str(total) + " members hold a privileged role (" + str(pct) +
            "%), within the " + str(round(MAX_PRIVILEGED_RATIO * 100, 2)) + "% threshold. "
            "Roles observed: " + ", ".join(roles_seen) + "."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(count) + " of " + str(total) + " members hold a privileged role (" + str(pct) +
            "%), exceeding the " + str(round(MAX_PRIVILEGED_RATIO * 100, 2)) + "% threshold. "
            "Roles observed: " + ", ".join(roles_seen) + "."
        ]
        recommendations = [
            "Reduce members holding admin, owner, primary_owner or membership_admin to " +
            str(round(MAX_PRIVILEGED_RATIO * 100, 2)) + "% of the roster or fewer."
        ]

    return create_response(
        result={
            "isPrivilegedAccessLimited": result,
            "totalMembers": total,
            "privilegedMembers": count,
            "privilegedRatio": pct,
            "privilegedRolesObserved": roles_seen,
            "maxAllowedRatio": round(MAX_PRIVILEGED_RATIO * 100, 2),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalMembers": total, "privilegedMembers": count},
        metadata=METADATA,
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isPrivilegedAccessLimited": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
