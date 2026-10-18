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


def has_sms_signal(obj, depth):
    """Recursively search a dict/list for a key mentioning 'sms' with a
    truthy / enabled-like value. Depth-limited to avoid runaway recursion."""
    if depth <= 0:
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_lower = str(k).lower()
            if "sms" in key_lower:
                if v is True:
                    return True
                if isinstance(v, str) and v.lower() in ("enabled", "active", "true", "configured", "verified"):
                    return True
                if isinstance(v, dict):
                    if v.get("enabled") is True or v.get("active") is True:
                        return True
                    status_val = v.get("status")
                    if isinstance(status_val, str) and status_val.lower() in ("enabled", "active", "configured", "verified"):
                        return True
            if isinstance(v, (dict, list)):
                if has_sms_signal(v, depth - 1):
                    return True
    elif isinstance(obj, list):
        for item in obj:
            if has_sms_signal(item, depth - 1):
                return True
    return False


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
        if not isinstance(total_count, int):
            total_count = len(users)
    else:
        users = []
        total_count = 0

    sms_enabled_users = []
    any_sms_field_seen = False

    for user in users:
        if not isinstance(user, dict):
            continue
        mfa_obj = user.get("mfa")
        mfa_enrollment_obj = user.get("mfaEnrollment")

        user_has_sms = False
        if isinstance(mfa_obj, dict):
            if has_sms_signal(mfa_obj, 4):
                user_has_sms = True
                any_sms_field_seen = True
        if isinstance(mfa_enrollment_obj, dict):
            if has_sms_signal(mfa_enrollment_obj, 4):
                user_has_sms = True
                any_sms_field_seen = True

        if user_has_sms:
            username = user.get("username") or user.get("email") or user.get("_id") or "unknown"
            sms_enabled_users.append(username)

    sms_count = len(sms_enabled_users)
    sample_size = len(users)

    if any_sms_field_seen:
        pass_reasons = [
            f"Found {sms_count} of {sample_size} scanned system users with an SMS-related "
            f"factor field set to an enabled/active state in their mfa or mfaEnrollment object."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Scanned {sample_size} system users (of {total_count} total reported by the API); "
            "none of the mfa or mfaEnrollment objects exposed an SMS-specific factor field with "
            "an enabled/active value, so the SMS-factor-enabled user count is reported as 0."
        ]
        recommendations = [
            "If SMS is used as an MFA factor in this JumpCloud org, verify the field name JumpCloud "
            "returns for SMS factor status on systemusers, since none was observed in the sampled records."
        ]

    result = {
        "smsFactorEnabledUsersCount": sms_count,
        "totalUsersScanned": sample_size,
        "totalUsersReported": total_count,
    }

    input_summary = {
        "totalUsersScanned": sample_size,
        "totalUsersReported": total_count,
        "smsFactorEnabledUsersCount": sms_count,
    }

    metadata = {
        "transformationId": "smsFactorEnabledUsersCount",
        "vendor": "JumpCloud",
        "category": "identity-and-access-management",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud systemusers response proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"smsFactorEnabledUsersCount": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "smsFactorEnabledUsersCount", "vendor": "JumpCloud",
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
