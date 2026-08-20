"""
Transformation: isPrivilegedAccessLimited
Vendor: Anthropic  |  Category: Artificial Intelligence
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


PRIVILEGED_ROLES = ("admin", "owner", "primary_owner", "membership_admin")
MAX_PRIVILEGED_RATIO = 0.25
SMALL_ORG_ALLOWANCE = 2  # two privileged members is a continuity floor, never a finding


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
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
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isPrivilegedAccessLimited": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
