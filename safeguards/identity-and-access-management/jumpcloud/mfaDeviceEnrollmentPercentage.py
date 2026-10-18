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
        items = data
        total_count = len(items)
    elif isinstance(data, dict):
        items = data.get("results")
        if not isinstance(items, list):
            items = []
        total_count_raw = data.get("totalCount")
        if isinstance(total_count_raw, int) and total_count_raw > 0:
            total_count = total_count_raw
        else:
            total_count = len(items)
    else:
        items = []
        total_count = 0

    enrolled_count = 0
    for user in items:
        if not isinstance(user, dict):
            continue
        is_enrolled = False
        if user.get("totp_enabled") is True:
            is_enrolled = True
        mfa_obj = user.get("mfa")
        # only mfa.configured is evidence; mfa.exclusion true means the user is EXEMPT from MFA
        if isinstance(mfa_obj, dict) and mfa_obj.get("configured") is True:
            is_enrolled = True
        enrollment_obj = user.get("mfaEnrollment")
        if isinstance(enrollment_obj, dict):
            for v in enrollment_obj.values():
                if v is True or (isinstance(v, str) and v.lower() == "enrolled"):
                    is_enrolled = True
                    break
        if is_enrolled:
            enrolled_count = enrolled_count + 1

    sample_note = ""
    if isinstance(data, dict):
        raw_total = data.get("totalCount")
        if isinstance(raw_total, int) and raw_total > 0 and raw_total != len(items):
            sample_note = (
                f"Note: totalCount ({raw_total}) differs from records received "
                f"({len(items)}); percentage computed over the {len(items)} records "
                f"actually returned to keep numerator/denominator in the same scope."
            )
            total_count = len(items)

    if total_count > 0:
        percentage = round((enrolled_count / total_count) * 100.0, 2)
    else:
        percentage = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_count == 0:
        fail_reasons.append("No system user records were returned; enrollment percentage cannot be computed.")
        recommendations.append("Verify the JumpCloud API key has access to the systemusers resource and that users exist.")
    else:
        detail = (
            f"{enrolled_count} of {total_count} system users show an MFA enrollment "
            f"signal (totp_enabled=true, an enabled factor in mfa{{}}, or an enrolled "
            f"state in mfaEnrollment{{}})."
        )
        if percentage >= 90.0:
            pass_reasons.append(f"MFA device enrollment percentage is {percentage}%. {detail}")
        else:
            fail_reasons.append(f"MFA device enrollment percentage is only {percentage}%. {detail}")
            recommendations.append(
                "Require MFA enrollment for all active JumpCloud system users and follow up "
                "with users lacking totp_enabled or an enrolled mfaEnrollment factor."
            )
        if sample_note:
            recommendations.append(sample_note)

    result = {
        "mfaDeviceEnrollmentPercentage": percentage,
        "enrolledUsers": enrolled_count,
        "totalUsers": total_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"enrolledUsers": enrolled_count, "totalUsers": total_count},
        metadata={
            "transformationId": "mfaDeviceEnrollmentPercentage",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud systemusers response proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"mfaDeviceEnrollmentPercentage": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "mfaDeviceEnrollmentPercentage", "vendor": "JumpCloud",
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
