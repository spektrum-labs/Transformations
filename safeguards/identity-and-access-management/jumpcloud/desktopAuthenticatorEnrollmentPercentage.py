
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


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    users = []
    total_count = 0

    if isinstance(data, list):
        users = data
        total_count = len(users)
    elif isinstance(data, dict):
        users = data.get("results") or data.get("data") or []
        if not isinstance(users, list):
            users = []
        raw_total = data.get("totalCount")
        if isinstance(raw_total, int) and raw_total > 0:
            total_count = raw_total
        else:
            total_count = len(users)

    enrolled_count = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        is_enrolled = False
        mfa_enrollment = u.get("mfaEnrollment")
        if isinstance(mfa_enrollment, dict) and mfa_enrollment.get("totpStatus") == "ENROLLED":
            is_enrolled = True
        elif u.get("totp_enabled") is True:
            is_enrolled = True
        if is_enrolled:
            enrolled_count = enrolled_count + 1

    if total_count and total_count > 0:
        percentage = round((enrolled_count / total_count) * 100, 2)
    else:
        percentage = 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_count and total_count > 0:
        pass_reasons.append(
            f"{enrolled_count} of {total_count} JumpCloud system users show totp_enabled=true or "
            f"mfaEnrollment.totpStatus='ENROLLED' (TOTP-based desktop authenticator app enrollment), "
            f"giving a {percentage} percent enrollment rate."
        )
        if percentage < 100:
            recommendations.append(
                f"Enforce TOTP desktop authenticator app enrollment for the remaining "
                f"{total_count - enrolled_count} users who currently show totp_enabled=false / "
                f"mfaEnrollment.totpStatus != 'ENROLLED'."
            )
    else:
        fail_reasons.append(
            "No system users were returned by listSystemUsers; cannot compute desktop authenticator "
            "enrollment percentage."
        )

    result = {
        "desktopAuthenticatorEnrollmentPercentage": percentage,
        "enrolledUsers": enrolled_count,
        "totalUsers": total_count,
    }

    input_summary = {
        "totalUsers": total_count,
        "enrolledUsers": enrolled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "desktopAuthenticatorEnrollmentPercentage",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud systemusers response proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"desktopAuthenticatorEnrollmentPercentage": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "desktopAuthenticatorEnrollmentPercentage", "vendor": "JumpCloud",
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
