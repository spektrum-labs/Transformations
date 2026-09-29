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


FACTOR_STATUS_FIELDS = ["totpStatus", "webAuthnStatus", "pushStatus", "smsStatus", "jcGoStatus"]


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        users = data
        total_count = len(users)
    elif isinstance(data, dict):
        users = data.get("results")
        if not isinstance(users, list):
            users = data.get("data")
        if not isinstance(users, list):
            users = []
        total_count = data.get("totalCount")
        if not isinstance(total_count, int):
            total_count = len(users)
    else:
        users = []
        total_count = 0

    inactive_factor_count = 0
    users_with_mfa_configured = 0
    users_enrolled_overall = 0
    inspected_examples = []

    for u in users:
        if not isinstance(u, dict):
            continue
        mfa = u.get("mfa") or {}
        mfa_enrollment = u.get("mfaEnrollment") or {}
        if not isinstance(mfa, dict):
            mfa = {}
        if not isinstance(mfa_enrollment, dict):
            mfa_enrollment = {}

        mfa_configured = bool(mfa.get("configured")) or bool(u.get("totp_enabled"))
        overall_status = mfa_enrollment.get("overallStatus")
        overall_enrolled = overall_status == "ENROLLED"

        if mfa_configured:
            users_with_mfa_configured = users_with_mfa_configured + 1
        if overall_enrolled:
            users_enrolled_overall = users_enrolled_overall + 1

        # Only inspect per-factor granularity for users who have at least gone
        # through MFA setup (configured or overall enrolled) - otherwise every
        # never-enrolled user's factors would be counted, which is not
        # "inactive", just "never used".
        if mfa_configured or overall_enrolled:
            user_inactive_here = 0
            for field_name in FACTOR_STATUS_FIELDS:
                status_value = mfa_enrollment.get(field_name)
                if status_value == "NOT_ENROLLED":
                    inactive_factor_count = inactive_factor_count + 1
                    user_inactive_here = user_inactive_here + 1
            if user_inactive_here > 0 and len(inspected_examples) < 5:
                username = u.get("username") or u.get("email") or u.get("_id") or "unknown"
                inspected_examples.append(f"{username} ({user_inactive_here} inactive factor(s))")

    result = {
        "inactiveMfaFactorsCount": inactive_factor_count,
        "usersInspected": len(users),
        "usersReportedByVendor": total_count,
        "usersWithMfaConfigured": users_with_mfa_configured,
        "usersEnrolledOverall": users_enrolled_overall,
    }

    if len(users) == 0:
        pass_reasons = []
        fail_reasons = ["No system user records were available to evaluate MFA factor activity."]
        recommendations = ["Verify listSystemUsers returns data; unable to assess inactive MFA factors."]
    elif inactive_factor_count == 0:
        pass_reasons = [
            f"Inspected {len(users)} system users' mfaEnrollment records ({FACTOR_STATUS_FIELDS}); "
            f"{users_with_mfa_configured} users have mfa.configured=true and {users_enrolled_overall} report "
            f"mfaEnrollment.overallStatus=ENROLLED, but none show a NOT_ENROLLED sub-factor alongside an "
            f"otherwise-configured/enrolled MFA state."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {inactive_factor_count} inactive MFA factor slot(s) (status=NOT_ENROLLED in mfaEnrollment "
            f"totpStatus/webAuthnStatus/pushStatus/smsStatus/jcGoStatus) across {users_with_mfa_configured} users "
            f"with mfa.configured=true or overallStatus=ENROLLED, out of {len(users)} users inspected. "
            f"Examples: {', '.join(inspected_examples)}."
        ]
        recommendations = [
            "Review users with partially-enrolled MFA factors in the JumpCloud admin console and either complete "
            "enrollment for the unused factor types or remove them from the required factor set."
        ]

    input_summary = {
        "usersInspected": len(users),
        "usersReportedByVendor": total_count,
        "inactiveMfaFactorsCount": inactive_factor_count,
        "usersWithMfaConfigured": users_with_mfa_configured,
        "usersEnrolledOverall": users_enrolled_overall,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "inactiveMfaFactorsCount",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud systemusers response proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"inactiveMfaFactorsCount": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "inactiveMfaFactorsCount", "vendor": "JumpCloud",
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
