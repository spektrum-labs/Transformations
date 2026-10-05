import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        users = data
        total_count = len(users)
    elif isinstance(data, dict):
        users = data.get("results") or data.get("data") or []
        if not isinstance(users, list):
            users = []
        total_count = data.get("totalCount")
        if not isinstance(total_count, int) or total_count <= 0:
            total_count = len(users)
    else:
        users = []
        total_count = 0

    enforced_count = 0
    active_users_considered = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        state = u.get("state")
        suspended = u.get("suspended")
        if suspended is True:
            continue
        if state is not None and state not in ("ACTIVATED", "STAGED"):
            continue
        active_users_considered = active_users_considered + 1
        if u.get("enable_user_portal_multifactor") is True:
            enforced_count = enforced_count + 1

    denominator = active_users_considered if active_users_considered > 0 else len(users)

    if denominator > 0:
        coverage_pct = round((enforced_count / denominator) * 100.0, 2)
    else:
        coverage_pct = round((enforced_count / max(denominator, 1)) * 100.0, 2)

    input_summary = {
        "totalUsersInResponse": len(users),
        "totalCountReported": total_count,
        "usersConsideredForCoverage": denominator,
        "usersWithMfaEnforced": enforced_count,
    }

    if denominator == 0:
        pass_reasons = []
        fail_reasons = ["No active system user records were found in the listSystemUsers response to evaluate MFA enforcement coverage."]
        recommendations = ["Verify the listSystemUsers API call returns user records for this tenant."]
    elif enforced_count == denominator:
        pass_reasons = [
            f"All {denominator} active/staged system users have enable_user_portal_multifactor=true, yielding {coverage_pct}% MFA enforcement coverage."
        ]
        fail_reasons = []
        recommendations = []
    elif enforced_count == 0:
        pass_reasons = []
        fail_reasons = [
            f"0 of {denominator} active/staged system users have enable_user_portal_multifactor=true ({coverage_pct}% coverage)."
        ]
        recommendations = ["Enable user portal multifactor enforcement (enable_user_portal_multifactor) for all active JumpCloud system users, or apply an MFA-required authn policy."]
    else:
        pass_reasons = []
        fail_reasons = [
            f"{enforced_count} of {denominator} active/staged system users have enable_user_portal_multifactor=true, giving {coverage_pct}% MFA enforcement coverage (below full coverage)."
        ]
        recommendations = [f"Enable enable_user_portal_multifactor for the remaining {denominator - enforced_count} users who currently lack MFA enforcement."]

    return create_response(
        result={
            "mfaEnforcementCoveragePercentage": coverage_pct,
            "usersWithMfaEnforced": enforced_count,
            "usersConsidered": denominator,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "mfaEnforcementCoveragePercentage", "vendor": "JumpCloud", "category": "Identity and Access Management"},
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud systemusers response proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"mfaEnforcementCoveragePercentage": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "mfaEnforcementCoveragePercentage", "vendor": "JumpCloud",
                  "category": "identity-and-access-management"},
    )


def record_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    return None


def evidence_problem(data):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return "No JumpCloud systemusers envelope (results list) in the response; nothing to evaluate."
    users = data["results"]
    total = data.get("totalCount")
    if not isinstance(total, int) or isinstance(total, bool):
        return "The JumpCloud systemusers response has no totalCount, so a complete read cannot be shown."
    if total < 1 or len(users) == 0:
        return "JumpCloud reported no users; nothing to evaluate."
    if len(users) < total:
        return ("Read " + str(len(users)) + " of " + str(total) +
                " JumpCloud users; a partial read is not scored.")
    if not all(isinstance(u, dict) for u in users):
        return "The JumpCloud systemusers results are not user records."
    return None


def transform(input):
    data, validation = extract_input(input)
    problem = evidence_problem(data)
    if problem:
        return unevaluated(problem, validation)
    return transform_evidence(input)
